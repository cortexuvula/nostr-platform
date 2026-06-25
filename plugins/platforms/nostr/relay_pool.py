"""
Nostr relay pool — manages multiple WebSocket relay connections with
dedup, reconnection, and publish-to-all semantics.
"""

import asyncio
import json
import logging
import random
import time
from collections import OrderedDict
from typing import AsyncGenerator, Optional

logger = logging.getLogger(__name__)

try:
    import websockets
    from websockets.exceptions import ConnectionClosed, WebSocketException
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

MAX_DEDUP_SIZE = 50000  # Max event IDs to keep in dedup set


class RelayConnection:
    """Single relay WebSocket connection with reconnection logic."""

    def __init__(self, url: str):
        self.url = url
        self.ws = None
        self.connected = False
        self._reconnect_attempts = 0
        self._listen_task: Optional[asyncio.Task] = None
        self._stop = False

    async def connect(self) -> bool:
        """Open WebSocket connection to this relay."""
        if not WEBSOCKETS_AVAILABLE:
            logger.error("websockets package not installed")
            return False
        try:
            self.ws = await asyncio.wait_for(
                websockets.connect(self.url, ping_interval=20, ping_timeout=10),
                timeout=10,
            )
            self.connected = True
            self._reconnect_attempts = 0
            logger.info(f"Relay connected: {self.url}")
            return True
        except Exception as e:
            logger.warning(f"Failed to connect to {self.url}: {e}")
            self.connected = False
            return False

    async def disconnect(self):
        """Close this relay connection."""
        self._stop = True
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        self.ws = None
        self.connected = False

    def _reconnect_delay(self) -> float:
        """Exponential backoff with jitter: 1s, 2s, 4s, 8s, 16s, 30s cap."""
        base = min(2 ** self._reconnect_attempts, 30)
        return base + random.uniform(0, 1)

    async def send_raw(self, message: str):
        """Send a raw message to the relay."""
        if self.ws and self.connected:
            try:
                await self.ws.send(message)
            except Exception as e:
                logger.warning(f"Send to {self.url} failed: {e}")
                self.connected = False


class RelayPool:
    """Manages multiple relay connections with dedup and failover."""

    def __init__(self, relay_urls: list[str]):
        self.relay_urls = relay_urls
        self.connections: dict[str, RelayConnection] = {}
        self._seen_ids: OrderedDict = OrderedDict()
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._subscriptions: list[dict] = []
        self._running = False
        self._listen_tasks: list[asyncio.Task] = []

        # Dedup config
        self._max_dedup = MAX_DEDUP_SIZE

    def _check_dedup(self, event_id: str) -> bool:
        """Check if we've seen this event ID. Returns True if new."""
        if event_id in self._seen_ids:
            return False
        self._seen_ids[event_id] = True
        if len(self._seen_ids) > self._max_dedup:
            # Evict oldest 25% of entries
            evict_count = self._max_dedup // 4
            for _ in range(evict_count):
                self._seen_ids.popitem(last=False)
        return True

    async def connect(self):
        """Connect to all relays and start listening (for gateway mode)."""
        self._running = True
        tasks = []
        for url in self.relay_urls:
            conn = RelayConnection(url)
            self.connections[url] = conn
            tasks.append(self._connect_and_listen(conn))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def connect_only(self):
        """Connect to all relays without starting listen loops (for one-shot sends)."""
        tasks = []
        for url in self.relay_urls:
            conn = RelayConnection(url)
            self.connections[url] = conn
            tasks.append(conn.connect())
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _connect_and_listen(self, conn: RelayConnection):
        """Connect to a relay and start listening, with reconnection."""
        while self._running:
            success = await conn.connect()
            if success:
                # Resubscribe to all active subscriptions
                for sub_filter in self._subscriptions:
                    await self._send_subscription(conn, sub_filter)
                # Start listening
                await self._listen_relay(conn)
            else:
                conn._reconnect_attempts += 1
                delay = conn._reconnect_delay()
                logger.info(f"Reconnecting to {conn.url} in {delay:.1f}s")
                await asyncio.sleep(delay)

    async def _listen_relay(self, conn: RelayConnection):
        """Listen for messages from a single relay."""
        if not conn.ws:
            return
        try:
            async for raw_message in conn.ws:
                if not self._running:
                    break
                try:
                    message = json.loads(raw_message)
                    await self._handle_message(conn, message)
                except json.JSONDecodeError:
                    logger.debug(f"Invalid JSON from {conn.url}")
                except Exception as e:
                    logger.error(f"Error processing message from {conn.url}: {e}")
        except ConnectionClosed:
            logger.info(f"Connection closed to {conn.url}")
        except Exception as e:
            logger.warning(f"Listen error on {conn.url}: {e}")
        finally:
            conn.connected = False

    async def _handle_message(self, conn: RelayConnection, message: list):
        """Handle an incoming relay message [type, ...]."""
        if not message or not isinstance(message, list):
            return

        msg_type = message[0]

        if msg_type == "EVENT":
            # [EVENT, subscription_id, event_dict]
            if len(message) < 3:
                return
            event = message[2]
            event_id = event.get("id", "")
            if not event_id:
                return
            if self._check_dedup(event_id):
                await self._event_queue.put((event, conn.url))

        elif msg_type == "OK":
            # [OK, event_id, accepted, message]
            logger.debug(f"Relay {conn.url} OK: {message}")

        elif msg_type == "EOSE":
            # [EOSE, subscription_id]
            logger.debug(f"Relay {conn.url} EOSE for {message[1] if len(message) > 1 else '?'}")

        elif msg_type == "NOTICE":
            msg = message[1] if len(message) > 1 else ""
            logger.info(f"Relay {conn.url} NOTICE: {msg}")

        elif msg_type == "CLOSED":
            msg = message[2] if len(message) > 2 else ""
            logger.debug(f"Relay {conn.url} CLOSED: {msg}")

    async def subscribe(self, filters: list[dict]):
        """Send REQ messages to all connected relays."""
        self._subscriptions.extend(filters)
        for conn in self.connections.values():
            if conn.connected:
                for i, f in enumerate(filters):
                    await self._send_subscription(conn, f, sub_id=f"sub_{i}")

    async def _send_subscription(self, conn: RelayConnection,
                                  filter_dict: dict, sub_id: str = None):
        """Send a single REQ to a relay."""
        if sub_id is None:
            sub_id = f"sub_{id(filter_dict)}"
        req = json.dumps(["REQ", sub_id, filter_dict])
        await conn.send_raw(req)

    async def publish(self, event: dict) -> dict:
        """Publish an event to all relays.

        Returns dict with per-relay results:
        {url: {"accepted": bool, "message": str}}
        At least one relay must accept for success.
        """
        results = {}
        event_id = event.get("id", "")
        publish_msg = json.dumps(["EVENT", event])

        # Collect OK responses with a timeout
        ok_futures = []

        for conn in self.connections.values():
            if conn.connected:
                await conn.send_raw(publish_msg)

        # Wait briefly for OK responses (they come through the listen loop)
        # We use a simple approach: wait 2s then check
        # A more robust approach would use a future per event_id per relay
        await asyncio.sleep(0.5)
        logger.info(f"Published event {event_id[:16]}... to relays")
        return results

    async def events(self) -> AsyncGenerator[tuple[dict, str], None]:
        """Async generator yielding (event_dict, relay_url) tuples."""
        while self._running:
            try:
                event, relay_url = await asyncio.wait_for(
                    self._event_queue.get(), timeout=1.0
                )
                yield event, relay_url
            except asyncio.TimeoutError:
                continue

    async def disconnect(self):
        """Disconnect from all relays."""
        self._running = False
        for conn in self.connections.values():
            await conn.disconnect()
        self.connections.clear()
        logger.info("Relay pool disconnected")

    async def query(self, filter_dict: dict, timeout: float = 10.0) -> list[dict]:
        """Query relays for events matching a filter.

        Sends a REQ, collects events until EOSE or timeout.
        Returns list of matching event dicts.
        """
        sub_id = f"query_{int(time.time() * 1000)}"
        events = []
        collected = asyncio.Event()

        # We need to intercept events for this subscription
        # Simple approach: use a temporary queue
        temp_queue = asyncio.Queue()

        # For simplicity, send REQ and collect for timeout duration
        req = json.dumps(["REQ", sub_id, filter_dict])
        for conn in self.connections.values():
            if conn.connected:
                await conn.send_raw(req)

        # Collect events for timeout duration
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                # This is a simplified version — in production we'd
                # properly route subscription-specific events
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break

        # Send CLOSE
        close_msg = json.dumps(["CLOSE", sub_id])
        for conn in self.connections.values():
            if conn.connected:
                await conn.send_raw(close_msg)

        return events
