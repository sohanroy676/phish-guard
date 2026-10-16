import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setCsrfToken } from "../api";
import Dashboard from "./Dashboard";
import History from "./History";

const item = {
  id: 1,
  created_at: "2026-06-01T12:00:00+00:00",
  kind: "url",
  display_host: "hxxp://evil[.]example",
  band: "high",
  model_reasons: [],
  rule_warnings: [],
  model_version: "v2",
};

const summary = {
  total: 3,
  by_band: { high: 1, suspicious: 0, low: 2, cant_assess: 0 },
  by_kind: { url: 2, email: 1 },
  trend: [{ date: "2026-06-01", count: 3 }],
  recent_high_risk: [item],
};

type FetchArgs = [string, RequestInit?];

function json(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200 });
}

function mockFetch(body: unknown) {
  const fn = vi.fn(async (...args: FetchArgs) => {
    void args;
    return json(body);
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

function deleteCall(fn: ReturnType<typeof mockFetch>) {
  return fn.mock.calls.find((c) => c[1]?.method === "DELETE");
}

class FakeEventSource {
  static last: FakeEventSource;
  listeners: Record<string, () => void> = {};
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(public url: string) {
    FakeEventSource.last = this;
  }
  addEventListener(name: string, fn: () => void) {
    this.listeners[name] = fn;
  }
  close() {
    this.closed = true;
  }
}

afterEach(() => vi.unstubAllGlobals());

describe("History", () => {
  it("shows the host as plain text, never a link", async () => {
    mockFetch({ items: [item] });
    render(<History />);
    const host = await screen.findByText("hxxp://evil[.]example");
    expect(host.closest("a")).toBeNull();
    expect(within(host.closest("tr")!).getByText("Likely phishing")).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("asks before deleting, then sends DELETE with the CSRF header", async () => {
    setCsrfToken("tok");
    const fetchMock = mockFetch({ items: [item], deleted: 1 });
    render(<History />);
    await screen.findByText("hxxp://evil[.]example");
    await userEvent.click(screen.getByRole("button", { name: "Delete all" }));
    expect(deleteCall(fetchMock)).toBeUndefined();
    await userEvent.click(screen.getByRole("button", { name: "Yes, delete everything" }));
    expect(deleteCall(fetchMock)?.[1]?.headers).toMatchObject({ "X-CSRF-Token": "tok" });
  });

  it("cancelling the confirmation deletes nothing", async () => {
    const fetchMock = mockFetch({ items: [item] });
    render(<History />);
    await screen.findByText("hxxp://evil[.]example");
    await userEvent.click(screen.getByRole("button", { name: "Delete all" }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(deleteCall(fetchMock)).toBeUndefined();
  });

  it("filters by band through the query string", async () => {
    const fetchMock = mockFetch({ items: [] });
    render(<History />);
    await screen.findByText("No checks yet.");
    await userEvent.selectOptions(screen.getByLabelText("Result"), "high");
    await waitFor(() =>
      expect(fetchMock.mock.calls.map((c) => c[0])).toContain("/api/history?band=high"),
    );
  });
});

describe("Dashboard", () => {
  it("refetches the summary when a live event arrives and closes the stream on unmount", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    const fetchMock = mockFetch(summary);
    const { unmount } = render(<Dashboard />);
    expect(await screen.findByText("Last 30 days")).toBeInTheDocument();
    expect(FakeEventSource.last.url).toBe("/api/events");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    act(() => FakeEventSource.last.listeners["analysis"]());
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    unmount();
    expect(FakeEventSource.last.closed).toBe(true);
  });

  it("never offers a Safe label", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    mockFetch(summary);
    render(<Dashboard />);
    await screen.findByText("Last 30 days");
    expect(document.body.textContent).not.toMatch(/safe/i);
  });
});
