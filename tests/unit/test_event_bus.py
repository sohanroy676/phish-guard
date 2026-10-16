import asyncio

from phishguard.app.events import QUEUE_SIZE, EventBus
from phishguard.app.routers.events import event_stream


async def settle():
    await asyncio.sleep(0.05)  # lets call_soon_threadsafe callbacks run


def test_event_reaches_only_its_own_user():
    async def run():
        bus = EventBus()
        a, b = bus.subscribe(1), bus.subscribe(2)
        await asyncio.to_thread(bus.publish, 1)  # publish from another thread, like a route
        await settle()
        assert a.queue.qsize() == 1 and b.queue.qsize() == 0
        assert a.queue.get_nowait() == {"type": "analysis"}

    asyncio.run(run())


def test_unsubscribe_stops_delivery_and_cleans_up():
    async def run():
        bus = EventBus()
        a = bus.subscribe(1)
        bus.unsubscribe(a)
        bus.unsubscribe(a)  # twice is harmless
        bus.publish(1)
        await settle()
        assert a.queue.empty() and bus._subs == {}

    asyncio.run(run())


def test_slow_reader_drops_oldest_and_never_blocks():
    async def run():
        bus = EventBus()
        a = bus.subscribe(1)
        for i in range(QUEUE_SIZE + 5):
            bus.publish(1, {"type": "analysis", "n": i})
        await settle()
        assert a.queue.qsize() == QUEUE_SIZE
        assert a.queue.get_nowait()["n"] == 5

    asyncio.run(run())


def test_publish_with_closed_loop_does_not_raise():
    bus = EventBus()
    loop = asyncio.new_event_loop()
    sub = loop.run_until_complete(_subscribe(bus, 1))
    loop.close()
    bus.publish(1)  # swallowed, and the dead subscriber is dropped
    assert sub not in bus._subs.get(1, set())


async def _subscribe(bus, user_id):
    return bus.subscribe(user_id)


def test_stream_emits_sse_frames_and_unsubscribes_on_disconnect():
    async def run():
        bus = EventBus()
        gone = False

        async def is_disconnected():
            return gone

        stream = event_stream(bus, 7, is_disconnected, poll_seconds=0.01)
        assert await anext(stream) == "retry: 3000\n\n"
        bus.publish(7)
        frame = await asyncio.wait_for(anext(stream), 2)
        assert frame == 'event: analysis\ndata: {"type": "analysis"}\n\n'
        gone = True
        assert [f async for f in stream] == []
        assert bus._subs == {}

    asyncio.run(run())
