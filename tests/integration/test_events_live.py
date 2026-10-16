"""SSE needs a real server: TestClient cannot read an endless stream."""

import queue
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from conftest import PASSWORD
from phishguard.app.main import create_app


@pytest.fixture
def live(settings):
    app = create_app(settings)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/api/health").status_code == 200:
                break
        except httpx.TransportError:
            time.sleep(0.05)
    yield app, base
    server.should_exit = True
    thread.join(timeout=10)


def register(base, email):
    client = httpx.Client(base_url=base)
    response = client.post(
        "/api/auth/register", json={"email": email, "password": PASSWORD, "consent": True}
    )
    assert response.status_code == 201
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return client


def listen(client, lines):
    try:
        with client.stream("GET", "/api/events", timeout=httpx.Timeout(10, read=10)) as response:
            lines.put(response.headers["content-type"])
            for line in response.iter_lines():
                lines.put(line)
    except httpx.HTTPError:  # the test closed the client while the stream was open
        pass


def wait_for(lines, wanted, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if lines.get(timeout=0.1) == wanted:
                return True
        except queue.Empty:
            pass
    return False


def test_stream_delivers_own_events_and_never_other_users(live):
    app, base = live
    alice, bob = register(base, "alice@example.com"), register(base, "bob@example.com")
    lines: queue.Queue = queue.Queue()
    threading.Thread(target=listen, args=(alice, lines), daemon=True).start()
    assert lines.get(timeout=5).startswith("text/event-stream")
    for _ in range(100):  # wait until the server has registered the subscriber
        if app.state.events._subs:
            break
        time.sleep(0.05)

    assert bob.post("/api/analyze/url", json={"url": "https://bob-only.com"}).status_code == 200
    assert not wait_for(lines, "event: analysis", 1.5), "Alice saw Bob's event"

    assert alice.post("/api/analyze/url", json={"url": "https://alice.com"}).status_code == 200
    assert wait_for(lines, "event: analysis", 3), "Alice's own event never arrived"
    assert wait_for(lines, 'data: {"type": "analysis"}', 1)
    alice.close()
    bob.close()


def test_stream_requires_login(live):
    _, base = live
    assert httpx.get(f"{base}/api/events").status_code == 401
