import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./auth";

function mockMe(loggedIn: boolean) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      loggedIn
        ? new Response(JSON.stringify({ email: "a@b.com", csrf_token: "tok" }), { status: 200 })
        : new Response(JSON.stringify({ detail: "Please log in." }), { status: 401 }),
    ),
  );
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("App shell", () => {
  it("shows the four nav links", async () => {
    mockMe(true);
    renderAt("/analyze");
    await screen.findByRole("heading", { name: "Analyze" });
    const nav = screen.getByRole("navigation", { name: "Main" });
    const labels = Array.from(nav.querySelectorAll("a")).map((a) => a.textContent);
    expect(labels).toEqual(["Analyze", "History", "Dashboard", "Privacy"]);
  });

  it("redirects / to the analyze page when logged in", async () => {
    mockMe(true);
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Analyze" })).toBeInTheDocument();
  });

  it("sends a logged-out visitor from the analyze page to login", async () => {
    mockMe(false);
    renderAt("/analyze");
    expect(await screen.findByRole("heading", { name: "Log in" })).toBeInTheDocument();
  });

  it("renders a not-found page for unknown routes", async () => {
    mockMe(true);
    renderAt("/nope");
    expect(await screen.findByRole("heading", { name: "Not found" })).toBeInTheDocument();
  });
});
