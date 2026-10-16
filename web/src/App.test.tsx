import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "./App";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("App shell", () => {
  it("shows the four nav links", () => {
    renderAt("/analyze");
    const nav = screen.getByRole("navigation", { name: "Main" });
    const labels = Array.from(nav.querySelectorAll("a")).map((a) => a.textContent);
    expect(labels).toEqual(["Analyze", "History", "Dashboard", "Privacy"]);
  });

  it("redirects / to the analyze page", () => {
    renderAt("/");
    expect(screen.getByRole("heading", { name: "Analyze" })).toBeInTheDocument();
  });

  it("renders a not-found page for unknown routes", () => {
    renderAt("/nope");
    expect(screen.getByRole("heading", { name: "Not found" })).toBeInTheDocument();
  });
});
