import { render, screen } from "@testing-library/react";
import type { EmailResult } from "../api";
import EmailResultCard from "./EmailResultCard";

const base: EmailResult = {
  band: "suspicious",
  headline: "Suspicious: be careful",
  advice: "Be careful.",
  footer: "PhishGuard is an advisory tool.",
  sender: "shop[.]example",
  model_reasons: [],
  rule_warnings: [],
  links: [],
  links_checked: true,
  truncated: false,
  header_checks: { available: true, message: "Header checks ran.", warnings: [] },
  model_note: "Weak signal for modern mail.",
  bulk_mail: { detected: false, authenticated: false },
};

// True when the note comes before the "Header checks" section in the page.
function noteFirst() {
  const note = screen.getByText(base.model_note);
  const headers = screen.getByRole("region", { name: "Header checks" });
  return Boolean(note.compareDocumentPosition(headers) & Node.DOCUMENT_POSITION_FOLLOWING);
}

describe("EmailResultCard model note", () => {
  it.each(["high", "suspicious"])("shows the note above the details for %s", (band) => {
    render(<EmailResultCard result={{ ...base, band }} />);
    expect(noteFirst()).toBe(true);
    expect(screen.getAllByText(base.model_note)).toHaveLength(1);
  });

  it.each(["low", "cant_assess"])("keeps the note at the bottom for %s", (band) => {
    render(<EmailResultCard result={{ ...base, band }} />);
    expect(noteFirst()).toBe(false);
    expect(screen.getAllByText(base.model_note)).toHaveLength(1);
  });
});

describe("EmailResultCard bulk mail", () => {
  it("says nothing about bulk mail when none was detected", () => {
    render(<EmailResultCard result={base} />);
    expect(screen.queryByText(/Bulk mail markers/)).toBeNull();
  });

  it("explains bulk markers and never calls authenticated mail safe", () => {
    render(
      <EmailResultCard result={{ ...base, bulk_mail: { detected: true, authenticated: true } }} />,
    );
    const text = screen.getByText(/Bulk mail markers found/).textContent ?? "";
    expect(text).toContain("does not prove the mail is safe");
  });

  it("marks a tracker link as not counted", () => {
    const link = {
      display_host: "click[.]list-manage[.]com",
      band: "cant_assess" as const,
      headline: "Can't assess",
      lookalike: false,
      discounted: true,
      rule_warnings: [],
    };
    render(<EmailResultCard result={{ ...base, links: [link] }} />);
    expect(screen.getByText(/real destination is hidden, so it is not counted/)).toBeTruthy();
  });
});
