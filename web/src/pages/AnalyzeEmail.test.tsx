import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import AnalyzeEmail from "./AnalyzeEmail";

const result = {
  band: "suspicious",
  headline: "Suspicious: be careful",
  advice: "Be careful.",
  footer: "PhishGuard is an advisory tool.",
  sender: "evil[.]example",
  model_reasons: ['The email text contains "<b>urgent</b>", a pattern common in phishing emails.'],
  rule_warnings: [],
  links: [
    {
      display_host: "hxxp://evil[.]example",
      band: "high",
      headline: "Likely phishing",
      lookalike: true,
      rule_warnings: [],
    },
  ],
  links_checked: true,
  truncated: false,
  header_checks: {
    available: false,
    message: "Header checks unavailable: paste the original email to enable them",
    warnings: [],
  },
  model_note: "The email model was trained on older legitimate mail.",
};

function mockFetch() {
  const fn = vi.fn(async () => new Response(JSON.stringify(result), { status: 200 }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

function setup() {
  render(
    <MemoryRouter>
      <AnalyzeEmail />
    </MemoryRouter>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("AnalyzeEmail", () => {
  it("has three tabs and switches between them", async () => {
    setup();
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual([
      "Fields",
      "Paste original",
      "Upload .eml",
    ]);
    await userEvent.click(screen.getByRole("tab", { name: "Paste original" }));
    expect(screen.getByLabelText("Original email source")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: "Upload .eml" }));
    expect(screen.getByLabelText(/Email file/)).toBeInTheDocument();
  });

  it("sends the fields as JSON and shows markup as plain text", async () => {
    const fetchMock = mockFetch();
    setup();
    await userEvent.type(screen.getByLabelText("Subject"), "Hello");
    await userEvent.click(screen.getByRole("button", { name: "Check email" }));
    expect(await screen.findByText(/<b>urgent<\/b>/)).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(JSON.parse(init.body as string)).toMatchObject({ mode: "fields", subject: "Hello" });
    expect(screen.getByText(/Header checks unavailable: paste the original email/)).toBeVisible();
    expect(screen.getByText(/Lookalike link/)).toBeInTheDocument();
    expect(screen.getByText(/older legitimate mail/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/%|\bsafe\b/i);
  });

  it("uploads a file as multipart without a JSON content type", async () => {
    const fetchMock = mockFetch();
    setup();
    await userEvent.click(screen.getByRole("tab", { name: "Upload .eml" }));
    const file = new File(["Subject: hi\n\nbody"], "mail.eml", { type: "message/rfc822" });
    await userEvent.upload(screen.getByLabelText(/Email file/), file);
    await userEvent.click(screen.getByRole("button", { name: "Check email" }));
    await screen.findByLabelText("Result");
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.headers as Record<string, string>)["Content-Type"]).toBeUndefined();
  });

  it("shows the server error and disables the button when empty", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ detail: "That is not a valid email file." }), {
            status: 422,
          }),
      ),
    );
    setup();
    expect(screen.getByRole("button", { name: "Check email" })).toBeDisabled();
    await userEvent.click(screen.getByRole("tab", { name: "Paste original" }));
    await userEvent.type(screen.getByLabelText("Original email source"), "junk");
    await userEvent.click(screen.getByRole("button", { name: "Check email" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not a valid email file");
  });
});
