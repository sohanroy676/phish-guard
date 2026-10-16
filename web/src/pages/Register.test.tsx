import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth";
import Register from "./Register";

const consentError = "You must agree to the privacy terms to create an account.";

function setup() {
  const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
    if (path === "/api/me") return new Response("{}", { status: 401 });
    const body = JSON.parse(String(init?.body));
    if (!body.consent)
      return new Response(JSON.stringify({ detail: consentError }), { status: 422 });
    return new Response(JSON.stringify({ email: body.email, csrf_token: "t" }), { status: 201 });
  });
  vi.stubGlobal("fetch", fetchMock);
  render(
    <MemoryRouter>
      <AuthProvider>
        <Register />
      </AuthProvider>
    </MemoryRouter>,
  );
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe("Register", () => {
  it("shows the server message when consent is unchecked, then succeeds once checked", async () => {
    const user = userEvent.setup();
    setup();
    await user.type(screen.getByLabelText("Email"), "a@b.com");
    await user.type(screen.getByLabelText(/Password/), "a-long-password");
    await user.click(screen.getByRole("button", { name: "Register" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(consentError);

    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Register" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("starts with the consent box unchecked", () => {
    setup();
    expect(screen.getByRole("checkbox")).not.toBeChecked();
  });
});
