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
STABLE_CONNECTION_SECONDS = 60  # Uptime after which reconnect backoff resets


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
            # NOTE: _reconnect_attempts is intentionally NOT reset here. The
            # reconnect loop in _connect_and_listen owns backoff tracking and
            # resets it only after a connection proves stable (see
            # STABLE_CONNECTION_SECONDS), so flapping relays ramp their delay.
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
        # Active subscriptions as (filter_dict, sub_id) tuples. The sub_id is
        # stable across reconnects so resubscribe reuses the same id, and
        # globally unique so two subscribe() calls never collide.
        self._subscriptions: list[tuple[dict, str]] = []
        self._sub_counter = 0
        self._running = False
        self._listen_tasks: list[asyncio.Task] = []

        # Response routing.
        # _pending_ok[event_id] = list of {url: asyncio.Future} groups — each
        # publish() appends one group; an OK frame resolves the matching relay's
        # future in EVERY group, so concurrent publishes of the same event_id
        # all get their answers instead of clobbering each other.
        self._pending_ok: dict[str, list[dict[str, asyncio.Future]]] = {}
        # _active_queries[sub_id] = asyncio.Queue — events/EOSE for a one-shot
        # query() REQ are routed here instead of the global event stream.
        self._active_queries: dict[str, asyncio.Queue] = {}

        # Dedup config
        self._max_dedup = MAX_DEDUP_SIZE

    def _next_sub_id(self) -> str:
        """Return a process-unique subscription id."""
        self._sub_counter += 1
        return f"sub_{self._sub_counter}"

    def _check_dedup(self, event_id: str) -> bool:
        """Check if we've seen this event ID. Returns True if new."""
        if event_id in self._seen_ids:
            return False
        self._seen_ids[event_id] = True
        if len(self._seen_ids) > self._max_dedup:
            # Evict down to 75% of capacity in one shot, then stop. Evicting
            # on every insert once over the threshold causes the set size to
            # oscillate around the limit and wastes work under load.
            target = self._max_dedup - self._max_dedup // 4
            while len(self._seen_ids) > target:
                self._seen_ids.popitem(last=False)
        return True

    async def connect(self):
        """Connect to all relays and start listening in background (for gateway mode).

        Spawns one ``_connect_and_listen`` task per relay. Each task owns the
        full connect → listen → reconnect lifecycle for its relay, so the
        WebSocket is opened exactly once per relay (no double-connect / leak).
        Returns once every relay has attempted its initial connection.

        Safe to call again after a prior ``connect()``: any previously-running
        listen tasks are cancelled first, so two ``connect()`` calls can never
        spawn duplicate tasks on the same connection.
        """
        # If reconnecting the pool, cancel any lingering listen tasks from a
        # prior connect() before spawning fresh ones — otherwise both sets of
        # tasks would race on the same RelayConnection and double-open sockets.
        if self._listen_tasks:
            await self._cancel_listen_tasks()

        self._running = True
        for url in self.relay_urls:
            conn = RelayConnection(url)
            self.connections[url] = conn

        # Initial connect for every relay (so callers know what's up).
        tasks = [conn.connect() for conn in self.connections.values()]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Hand off each connection to its own background task. The task will
        # NOT re-connect if already connected; it only (re)connects after a
        # listen loop exits (i.e. a real drop). This avoids opening a second
        # WebSocket on top of the one opened above.
        self._listen_tasks = []
        for conn in self.connections.values():
            self._listen_tasks.append(
                asyncio.create_task(self._connect_and_listen(conn))
            )

    async def connect_only(self):
        """Connect to all relays without starting listen loops (for one-shot sends)."""
        tasks = []
        for url in self.relay_urls:
            conn = RelayConnection(url)
            self.connections[url] = conn
            tasks.append(conn.connect())
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _connect_and_listen(self, conn: RelayConnection):
        """Own the connect → listen → reconnect lifecycle for one relay.

        Does NOT reconnect if ``conn`` is already connected (the initial
        connection is made by ``connect()``); it only (re)connects after a
        listen loop exits, i.e. after a genuine drop.

        Backoff uses ``conn._reconnect_attempts``. It is incremented on every
        drop and only reset when a connection stays up longer than
        ``STABLE_CONNECTION_SECONDS`` — so a relay that flaps (connect then
        immediately drop) ramps up its backoff, while a normally-stable relay
        that occasionally drops resets to a short delay next time.
        """
        while self._running:
            try:
                if not conn.connected:
                    success = await conn.connect()
                    if not success:
                        conn._reconnect_attempts += 1
                        delay = conn._reconnect_delay()
                        logger.info(f"Reconnecting to {conn.url} in {delay:.1f}s")
                        await asyncio.sleep(delay)
                        continue

                # Resubscribe to all active subscriptions on a fresh connection.
                for sub_filter, sub_id in self._subscriptions:
                    await self._send_subscription(conn, sub_filter, sub_id=sub_id)

                # Listen until the socket drops. Remember how long it stayed up.
                connected_at = time.time()
                await self._listen_relay(conn)
                uptime = time.time() - connected_at

                # Reset backoff only if the connection was stable long enough;
                # a connection that dropped quickly keeps accumulating backoff.
                if uptime >= STABLE_CONNECTION_SECONDS:
                    conn._reconnect_attempts = 0
                else:
                    conn._reconnect_attempts += 1
            except asyncio.CancelledError:
                # Shutdown signal from disconnect()/reconnect — let it propagate.
                raise
            except Exception as e:
                # Don't let an unexpected error kill the whole reconnect loop
                # and orphan this relay forever; back off and try again.
                logger.warning(f"Error in {conn.url} connect/listen cycle: {e}")
                uptime = 0
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
            sub_id = message[1] if len(message) > 1 else ""
            event = message[2]
            event_id = event.get("id", "")
            if not event_id:
                return
            # Route to a one-shot query if the subscription matches one,
            # otherwise deliver to the global event stream (with dedup).
            if sub_id in self._active_queries:
                await self._active_queries[sub_id].put(event)
            elif self._check_dedup(event_id):
                await self._event_queue.put((event, conn.url))

        elif msg_type == "OK":
            # [OK, event_id, accepted, message]
            if len(message) >= 3:
                ok_event_id = message[1]
                accepted = bool(message[2])
                ok_msg = message[3] if len(message) > 3 else ""
                # Resolve the matching relay's future in every pending group
                # for this event_id (concurrent publishes of the same event).
                for group in self._pending_ok.get(ok_event_id, []):
                    fut = group.get(conn.url)
                    if fut and not fut.done():
                        fut.set_result({"accepted": accepted, "message": ok_msg})
            logger.debug(f"Relay {conn.url} OK: {message}")

        elif msg_type == "EOSE":
            # [EOSE, subscription_id]
            eose_sub_id = message[1] if len(message) > 1 else ""
            logger.debug(f"Relay {conn.url} EOSE for {eose_sub_id}")
            # Signal a one-shot query() that stored events are delivered.
            q = self._active_queries.get(eose_sub_id)
            if q is not None:
                await q.put(None)  # sentinel meaning "EOSE"

        elif msg_type == "NOTICE":
            msg = message[1] if len(message) > 1 else ""
            logger.info(f"Relay {conn.url} NOTICE: {msg}")

        elif msg_type == "CLOSED":
            msg = message[2] if len(message) > 2 else ""
            logger.debug(f"Relay {conn.url} CLOSED: {msg}")

    async def subscribe(self, filters: list[dict]) -> list[str]:
        """Send REQ messages to all connected relays.

        Assigns each filter a process-unique, stable sub_id so repeated
        ``subscribe()`` calls never collide on the relay, and reconnects
        (handled in ``_connect_and_listen``) reuse the same id. Returns the
        list of assigned sub_ids.
        """
        assigned = []
        for f in filters:
            sub_id = self._next_sub_id()
            self._subscriptions.append((f, sub_id))
            assigned.append(sub_id)
            for conn in self.connections.values():
                if conn.connected:
                    await self._send_subscription(conn, f, sub_id=sub_id)
        return assigned

    async def _send_subscription(self, conn: RelayConnection,
                                  filter_dict: dict, sub_id: str):
        """Send a single REQ to a relay using the given sub_id."""
        req = json.dumps(["REQ", sub_id, filter_dict])
        await conn.send_raw(req)

    async def publish(self, event: dict, timeout: float = 5.0) -> dict:
        """Publish an event to all connected relays and await OK frames.

        Returns ``{url: {"accepted": bool, "message": str}}`` for each relay
        that responded within *timeout*. Relays that don't respond are
        omitted from the result. The caller can check ``any(r["accepted"]
        for r in results.values())`` to confirm at least one acceptance.
        """
        event_id = event.get("id", "")
        publish_msg = json.dumps(["EVENT", event])

        # Register a future per connected relay, then send. Concurrent
        # publishes of the same event_id each append their own group so an
        # arriving OK resolves every group's matching future (no clobbering).
        relay_futures: dict[str, asyncio.Future] = {}
        targets = [c for c in self.connections.values() if c.connected]
        loop = asyncio.get_running_loop()
        for conn in targets:
            fut = loop.create_future()
            relay_futures[conn.url] = fut
        groups = self._pending_ok.setdefault(event_id, [])
        groups.append(relay_futures)

        try:
            for conn in targets:
                await conn.send_raw(publish_msg)

            # Wait for every relay's OK (or timeout). Collect as they land.
            results = {}
            pending = dict(relay_futures)
            deadline = time.time() + timeout
            while pending:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                done, _ = await asyncio.wait(
                    pending.values(),
                    timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for fut in done:
                    if fut.cancelled() or fut.exception() is not None:
                        continue
                    # Find which url this future belongs to.
                    for url, f in list(pending.items()):
                        if f is fut:
                            results[url] = fut.result()
                            del pending[url]
                            break
            logger.info(
                f"Published event {event_id[:16]}... "
                f"({len(results)}/{len(targets)} relays acknowledged)"
            )
            return results
        finally:
            # Remove ONLY this publish's group (by identity) so a concurrent
            # publish of the same event_id keeps its registration intact.
            groups = self._pending_ok.get(event_id, [])
            self._pending_ok[event_id] = [
                g for g in groups if g is not relay_futures
            ]
            if not self._pending_ok[event_id]:
                self._pending_ok.pop(event_id, None)
            # Cancel any of our futures that never resolved (no resource leak).
            for fut in relay_futures.values():
                if not fut.done():
                    fut.cancel()

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

    async def _cancel_listen_tasks(self):
        """Cancel and await all per-relay listen/reconnect tasks.

        Used by both ``connect()`` (to clear stale tasks before reconnecting)
        and ``disconnect()``. Cancellation is the normal shutdown signal: a
        CancelledError propagating out of a sleeping/listening task is
        expected and suppressed; genuine exceptions are logged, not swallowed
        silently, so a dead task doesn't hide a real failure.
        """
        for task in self._listen_tasks:
            task.cancel()
        for task in self._listen_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.warning(f"Listen task ended with error during shutdown: {e}")
        self._listen_tasks.clear()

    async def disconnect(self):
        """Disconnect from all relays."""
        self._running = False
        # Stop the per-relay listen/reconnect tasks.
        await self._cancel_listen_tasks()
        for conn in self.connections.values():
            await conn.disconnect()
        self.connections.clear()
        logger.info("Relay pool disconnected")

    async def query(self, filter_dict: dict, timeout: float = 10.0) -> list[dict]:
        """Query relays for events matching a filter.

        Sends a REQ, collects matching EVENTs until every relay sends EOSE
        (or *timeout* elapses). Returns the list of matching event dicts.
        Uses a dedicated queue routed by ``_handle_message`` so results are
        not mixed into the global event stream.
        """
        sub_id = self._next_sub_id()
        results: list[dict] = []
        seen: set[str] = set()  # local dedup: multiple relays serve the same event
        queue: asyncio.Queue = asyncio.Queue()
        self._active_queries[sub_id] = queue

        targets = [c for c in self.connections.values() if c.connected]
        req = json.dumps(["REQ", sub_id, filter_dict])
        try:
            for conn in targets:
                await conn.send_raw(req)

            # Wait until every relay has sent EOSE (each contributes one
            # None sentinel) or the overall timeout expires.
            deadline = time.time() + timeout
            eose_seen = 0
            while eose_seen < len(targets) and time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if item is None:  # EOSE sentinel from one relay
                    eose_seen += 1
                else:
                    eid = item.get("id")
                    if eid and eid not in seen:
                        seen.add(eid)
                        results.append(item)
        finally:
            # Always CLOSE and deregister, even on timeout/cancel.
            self._active_queries.pop(sub_id, None)
            close_msg = json.dumps(["CLOSE", sub_id])
            for conn in targets:
                if conn.connected:
                    try:
                        await conn.send_raw(close_msg)
                    except Exception:
                        pass

        return results
