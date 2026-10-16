"""In-process event bus for the live dashboard.

Events live in memory, so the app must run as a single worker. An event carries no
analysis data: it only tells that user's open pages to refetch.
"""

import asyncio
import threading
from dataclasses import dataclass, field

QUEUE_SIZE = 16


@dataclass(eq=False)
class Subscription:
    user_id: int
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(QUEUE_SIZE))


def _put_latest(queue: asyncio.Queue, event: dict) -> None:
    """Runs on the subscriber's loop. A slow reader loses its oldest event, not the app."""
    if queue.full():
        queue.get_nowait()
    queue.put_nowait(event)


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: dict[int, set[Subscription]] = {}

    def subscribe(self, user_id: int) -> Subscription:
        sub = Subscription(user_id, asyncio.get_running_loop())
        with self._lock:
            self._subs.setdefault(user_id, set()).add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            subs = self._subs.get(sub.user_id)
            if subs is not None:
                subs.discard(sub)
                if not subs:
                    del self._subs[sub.user_id]

    def publish(self, user_id: int, event: dict | None = None) -> None:
        """Safe to call from the threadpool that runs the sync routes."""
        event = event or {"type": "analysis"}
        with self._lock:
            targets = list(self._subs.get(user_id, ()))
        for sub in targets:
            try:
                sub.loop.call_soon_threadsafe(_put_latest, sub.queue, event)
            except RuntimeError:  # the subscriber's loop has already closed
                self.unsubscribe(sub)
