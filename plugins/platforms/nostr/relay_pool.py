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
        # NIP-42: per-connection auth state. The challenge is set by an
        # incoming AUTH message and is valid for the connection's lifetime.
        self.challenge: Optional[str] = None
        self.authenticated: bool = False

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
        # Background tasks (resubscribe, auth) spawned by _handle_message.
        # Tracked so they can be cancelled on disconnect — otherwise they
        # leak and send REQs to dead connections.
        self._background_tasks: set[asyncio.Task] = set()
        # Tracks (url, sub_id) pairs currently being resubscribed, so a
        # flapping relay sending multiple CLOSED frames doesn't spawn
        # duplicate resubscribe loops.
        self._resubscribing: set[tuple[str, str]] = set()

        # Response routing.
        # _pending_ok[event_id] = list of {url: asyncio.Future} groups — each
        # publish() appends one group; an OK frame resolves the matching relay's
        # future in EVERY group, so concurrent publishes of the same event_id
        # all get their answers instead of clobbering each other.
        self._pending_ok: dict[str, list[dict[str, asyncio.Future]]] = {}
        # _active_queries[sub_id] = asyncio.Queue — events/EOSE for a one-shot
        # query() REQ are routed here instead of the global event stream.
        self._active_queries: dict[str, asyncio.Queue] = {}

        # NIP-42 auth: the signer (EventSigner) is injected by the adapter so
        # the pool can sign kind-22242 auth events. When None, auth-required
        # signals are logged and the operation fails gracefully.
        self._signer = None
        # _pending_auth_ok[auth_event_id] = asyncio.Future — resolved by the OK
        # handler when the relay acks our kind-22242 auth event.
        self._pending_auth_ok: dict[str, asyncio.Future] = {}

        # Dedup config
        self._max_dedup = MAX_DEDUP_SIZE

    def set_signer(self, signer) -> None:
        """Inject the EventSigner used for NIP-42 authentication.

        Called by the adapter after construction. Without a signer, the pool
        cannot authenticate to auth-gated relays (graceful degradation).
        """
        self._signer = signer

    def _spawn_background(self, coro) -> asyncio.Task:
        """Create a tracked background task that is cleaned up on disconnect.

        Resubscribe and auth tasks spawned by _handle_message must be tracked
        so disconnect() can cancel them — otherwise they leak and send REQs to
        dead connections. Auto-removes from the set when done (no leak).
        """
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task

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
                asyncio.create_task(self._supervise_connection(conn))
            )

    async def connect_only(self):
        """Connect to all relays without starting listen loops (for one-shot sends)."""
        tasks = []
        for url in self.relay_urls:
            conn = RelayConnection(url)
            self.connections[url] = conn
            tasks.append(conn.connect())
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _supervise_connection(self, conn: RelayConnection):
        """Supervise the connect→listen→reconnect loop for one relay.

        Wraps ``_connect_and_listen`` so that if the loop dies with an
        unexpected error that escapes its own try/except (e.g. a C-level
        crash or MemoryError), the relay is restarted after a delay rather
        than staying dead forever.
        """
        while self._running:
            try:
                await self._connect_and_listen(conn)
                # Normal exit: _running became False (shutdown).
                if not self._running:
                    return
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(
                    f"Connection supervisor for {conn.url} crashed: {e}. "
                    f"Restarting in 10s."
                )
                conn.connected = False
                conn._reconnect_attempts += 1
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    raise

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
                # NIP-42: if this OK acks a kind-22242 auth event, resolve the
                # pending _authenticate future and mark the connection authed.
                auth_fut = self._pending_auth_ok.pop(ok_event_id, None)
                if auth_fut and not auth_fut.done():
                    auth_fut.set_result({"accepted": accepted, "message": ok_msg})
                    if accepted:
                        conn.authenticated = True
                # Resolve the matching relay's future in every pending group
                # for this event_id (concurrent publishes of the same event).
                for group in self._pending_ok.get(ok_event_id, []):
                    fut = group.get(conn.url)
                    if fut and not fut.done():
                        fut.set_result({"accepted": accepted, "message": ok_msg})
                # NIP-42: a rejected publish demanding auth triggers on-demand
                # authentication so the next attempt succeeds. Only for real
                # publish events (not our own auth-event OK, handled above).
                if (not accepted and ok_msg.startswith("auth-required:")
                        and not auth_fut and self._signer
                        and conn.challenge and not conn.authenticated):
                    self._spawn_background(self._authenticate(conn))
            logger.debug(f"Relay {conn.url} OK: {message}")

        elif msg_type == "AUTH":
            # NIP-42: ["AUTH", "<challenge>"]. The challenge is valid for the
            # connection's lifetime. We store it and authenticate on-demand
            # when an auth-required signal arrives (see CLOSED / OK branches).
            challenge = message[1] if len(message) > 1 else ""
            if challenge:
                conn.challenge = challenge
                logger.debug(f"Relay {conn.url} sent AUTH challenge")

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
            sub_id = message[1] if len(message) > 1 else ""
            msg = message[2] if len(message) > 2 else ""
            logger.info(f"Relay {conn.url} CLOSED sub {sub_id}: {msg}")

            # NIP-42: "restricted:" means the action is forbidden for this
            # account — retrying is futile, so don't resubscribe.
            if msg.startswith("restricted:"):
                return

            # NIP-42: "auth-required:" means we must authenticate before the
            # relay will serve this subscription. Do so on-demand, then
            # resubscribe. Without a signer or without a stored challenge,
            # auth is impossible — fall through to plain resubscribe (which
            # will likely get CLOSED again, but avoids a hard failure).
            if (msg.startswith("auth-required:") and self._signer
                    and conn.challenge and not conn.authenticated):
                self._spawn_background(self._auth_then_resubscribe(conn, sub_id, msg))
                return

            # If the relay closed a subscription (e.g. transient error),
            # resubscribe after a short delay so we don't permanently lose
            # events from this relay. Only resubscribe if the pool is still
            # running and the subscription is still active.
            if self._running and sub_id:
                for f, sid in self._subscriptions:
                    if sid == sub_id:
                        # Guard against duplicate resubscribe tasks for the
                        # same sub_id on the same connection (some relays
                        # send multiple CLOSED frames). If a resubscribe is
                        # already in progress, skip.
                        task_key = (conn.url, sub_id)
                        if task_key not in self._resubscribing:
                            self._resubscribing.add(task_key)
                            self._spawn_background(
                                self._resubscribe_tracked(conn, f, sub_id, msg, task_key)
                            )
                        break

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

    async def _authenticate(self, conn: RelayConnection,
                             timeout: float = 5.0) -> bool:
        """NIP-42: authenticate to *conn* by signing and sending a kind-22242
        event in response to its stored challenge.

        Returns True on a successful auth (relay OK accepted=True), False on
        failure, timeout, missing signer, or missing challenge. On success,
        ``conn.authenticated`` is set so subsequent operations skip re-auth.
        """
        if not self._signer or not conn.challenge:
            return False

        # Sign the kind-22242 auth event per NIP-42: tags MUST be relay+challenge.
        auth_event = self._signer.sign_event(
            kind=22242,
            content="",
            tags=[
                ["relay", conn.url],
                ["challenge", conn.challenge],
            ],
        )
        event_id = auth_event.get("id", "")

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending_auth_ok[event_id] = fut

        try:
            # NIP-42: send as an AUTH message (NOT EVENT).
            await conn.send_raw(json.dumps(["AUTH", auth_event]))
            result = await asyncio.wait_for(fut, timeout=timeout)
            return bool(result.get("accepted"))
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"NIP-42 auth to {conn.url} failed: {e}")
            return False
        finally:
            self._pending_auth_ok.pop(event_id, None)

    async def _auth_then_resubscribe(self, conn: RelayConnection,
                                      sub_id: str, reason: str):
        """Authenticate to *conn*, then re-issue the CLOSED subscription.

        NIP-42 flow for auth-required subscriptions: authenticate, then
        re-send the REQ (the original subscription was terminated by CLOSED).
        """
        if not self._running or not conn.connected:
            return
        success = await self._authenticate(conn)
        if not success:
            logger.warning(
                f"NIP-42 auth to {conn.url} failed ({reason}); "
                f"subscription {sub_id} will not be retried on this relay"
            )
            return
        # Find the filter for this subscription and re-send the REQ.
        for f, sid in self._subscriptions:
            if sid == sub_id:
                try:
                    await self._send_subscription(conn, f, sub_id=sub_id)
                    logger.info(
                        f"Resubscribed to {conn.url} for {sub_id} after NIP-42 auth"
                    )
                except Exception as e:
                    logger.warning(f"Post-auth resubscribe to {conn.url} failed: {e}")
                break

    async def _resubscribe_tracked(self, conn: RelayConnection,
                                    filter_dict: dict, sub_id: str,
                                    reason: str, task_key: tuple):
        """Wrapper that clears the resubscribe guard on completion."""
        try:
            await self._resubscribe_after(conn, filter_dict, sub_id, reason)
        finally:
            self._resubscribing.discard(task_key)

    async def _resubscribe_after(self, conn: RelayConnection,
                                 filter_dict: dict, sub_id: str,
                                 reason: str, max_retries: int = 5):
        """Resubscribe to a closed subscription after a backoff delay.

        Relays like ``nostr.wine`` and ``eden.nostr.land`` close
        subscriptions with ``auth-required`` — this gives the client time
        to authenticate (which our relay pool doesn't currently do) and
        then retries the REQ.  Backoff: 5s, 10s, 20s, 40s, 60s cap.

        After ``max_retries`` attempts the subscription is abandoned for
        this relay; the relay's ``_connect_and_listen`` loop will
        resubscribe on the next reconnect cycle anyway.
        """
        for attempt in range(1, max_retries + 1):
            if not self._running or not conn.connected:
                return
            delay = min(5 * (2 ** (attempt - 1)), 60)
            logger.info(
                f"Resubscribing to {conn.url} for sub {sub_id} "
                f"({reason}) in {delay}s (attempt {attempt}/{max_retries})"
            )
            await asyncio.sleep(delay)
            if not self._running or not conn.connected:
                return
            # Check the subscription hasn't been removed (e.g. pool disconnect).
            if not any(sid == sub_id for _, sid in self._subscriptions):
                return
            try:
                await self._send_subscription(conn, filter_dict, sub_id=sub_id)
                logger.info(
                    f"Resubscribed to {conn.url} for sub {sub_id} "
                    f"(attempt {attempt})"
                )
                return  # Sent successfully — relay will EVENT or CLOSED again
            except Exception as e:
                logger.warning(
                    f"Resubscribe attempt {attempt} to {conn.url} failed: {e}"
                )
        logger.warning(
            f"Gave up resubscribing to {conn.url} for sub {sub_id} "
            f"after {max_retries} attempts"
        )

    async def publish(self, event: dict, timeout: float = 5.0,
                      only_urls: Optional[list] = None) -> dict:
        """Publish an event to all connected relays and await OK frames.

        Returns ``{url: {"accepted": bool, "message": str}}`` for each relay
        that responded within *timeout*. Relays that don't respond are
        omitted from the result. The caller can check ``any(r["accepted"]
        for r in results.values())`` to confirm at least one acceptance.

        If *only_urls* is given, only pool connections whose URL is in the
        set are targeted — used by ``publish_to`` to deliver a gift wrap to
        a recipient's specific inbox relays that happen to be in our pool.
        """
        event_id = event.get("id", "")
        publish_msg = json.dumps(["EVENT", event])

        # Register a future per connected relay, then send. Concurrent
        # publishes of the same event_id each append their own group so an
        # arriving OK resolves every group's matching future (no clobbering).
        relay_futures: dict[str, asyncio.Future] = {}
        targets = [c for c in self.connections.values() if c.connected]
        if only_urls is not None:
            only_set = set(only_urls)
            targets = [c for c in targets if c.url in only_set]
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

    async def _publish_once(self, url: str, event: dict,
                             timeout: float = 5.0) -> dict:
        """Open a one-off connection to *url*, publish *event*, await OK.

        Self-contained: does NOT route through the pool's listen-task /
        ``_handle_message`` machinery, so it works for relays outside the
        pool. Opens a WebSocket, sends EVENT, reads frames until an OK for
        our event_id arrives or the timeout elapses, then closes. Returns
        ``{"accepted": bool, "message": str}``.

        Handles NIP-42 AUTH challenges: if the relay sends an AUTH message
        and the pool has a signer, signs a kind-22242 response so the relay
        accepts the publish.
        """
        event_id = event.get("id", "")
        publish_msg = json.dumps(["EVENT", event])
        conn = RelayConnection(url)
        try:
            success = await conn.connect()
            if not success:
                return {"accepted": False, "message": "connect failed"}
            await conn.send_raw(publish_msg)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(conn.ws.recv(),
                                                  timeout=deadline - time.time())
                except asyncio.TimeoutError:
                    break
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(msg, list) or not msg:
                    continue
                # NIP-42: respond to AUTH challenges so auth-gated external
                # relays accept the publish. Reuse the pool's signer if set.
                if msg[0] == "AUTH" and len(msg) >= 2 and self._signer:
                    challenge = msg[1]
                    auth_event = self._signer.sign_event(
                        kind=22242, content="",
                        tags=[["relay", url], ["challenge", challenge]],
                    )
                    await conn.send_raw(json.dumps(["AUTH", auth_event]))
                    continue
                if (len(msg) >= 3 and msg[0] == "OK"
                        and msg[1] == event_id):
                    return {"accepted": bool(msg[2]),
                            "message": msg[3] if len(msg) > 3 else ""}
            return {"accepted": False, "message": "timeout"}
        except Exception as e:
            return {"accepted": False, "message": f"error: {e}"}
        finally:
            try:
                await conn.disconnect()
            except Exception:
                pass

    async def publish_to(self, event: dict, urls: list,
                          timeout: float = 5.0) -> dict:
        """Publish *event* to a specific set of relay *urls*.

        URLs that are already pool members go through ``publish`` (reusing
        existing connections and listen-task OK routing); URLs not in the
        pool are handled by concurrent ``_publish_once`` one-off connections.
        Returns ``{url: {"accepted": "message"}}`` for every URL attempted.

        This is the NIP-17 recipient-relay-delivery path: the caller passes
        the recipient's kind-10050 inbox relays so the gift wrap reaches
        where the recipient actually listens.
        """
        if not urls:
            return {}
        pool_urls = {c.url for c in self.connections.values() if c.connected}
        in_pool = [u for u in urls if u in pool_urls]
        external = [u for u in urls if u not in pool_urls]

        results: dict[str, dict] = {}
        if in_pool:
            results.update(await self.publish(event, timeout=timeout,
                                               only_urls=in_pool))
        if external:
            ext_results = await asyncio.gather(
                *(self._publish_once(u, event, timeout=timeout)
                  for u in external)
            )
            for url, res in zip(external, ext_results):
                results[url] = res
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
        # Cancel background tasks (resubscribe, auth) so they don't leak.
        for task in list(self._background_tasks):
            task.cancel()
        for task in list(self._background_tasks):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._background_tasks.clear()
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
