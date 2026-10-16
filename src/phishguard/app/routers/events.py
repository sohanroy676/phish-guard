import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from phishguard.app import auth
from phishguard.app.events import EventBus
from phishguard.app.models_db import SessionRow

router = APIRouter(prefix="/api")

POLL_SECONDS = 1.0
HEARTBEAT_TICKS = 15


async def event_stream(
    bus: EventBus,
    user_id: int,
    is_disconnected: Callable[[], Awaitable[bool]],
    poll_seconds: float = POLL_SECONDS,
) -> AsyncIterator[str]:
    sub = bus.subscribe(user_id)
    idle = 0
    try:
        yield "retry: 3000\n\n"
        while not await is_disconnected():
            try:
                event = await asyncio.wait_for(sub.queue.get(), timeout=poll_seconds)
            except TimeoutError:
                idle += 1
                if idle % HEARTBEAT_TICKS == 0:
                    yield ": keepalive\n\n"
                continue
            yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
    finally:
        bus.unsubscribe(sub)


@router.get("/events")
async def events(
    request: Request,
    row: SessionRow = Depends(auth.current_session),
    db: Session = Depends(auth.get_db),
) -> StreamingResponse:
    user_id = row.user_id
    db.close()  # a long-lived stream must not hold a database connection
    stream = event_stream(request.app.state.events, user_id, request.is_disconnected)
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
