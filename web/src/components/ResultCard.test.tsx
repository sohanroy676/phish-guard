import { render, screen, within } from "@testing-library/react";
import type { AnalysisResult } from "../api";
import ResultCard from "./ResultCard";

const base: AnalysisResult = {
  band: "suspicious",
  headline: "Suspicious: be careful",
  advice: "Be careful.",
  footer: "PhishGuard is an advisory tool.",
  display_host: "hxxp://paypal[.]com[.]evil[.]xyz",
  model_reasons: ['The host contains "xy", a pattern common in phishing links.'],
  rule_warnings: [
    {
      rule_id: "brand_impersonation",
      severity: "high",
      message: "Mentions paypal but is not that site.",
    },
  ],
};

describe("ResultCard", () => {
  it("keeps model reasons and rule warnings in two separate lists", () => {
    render(<ResultCard result={base} />);
    const reasons = screen.getByRole("list", { name: "Model reasons" });
    const warnings = screen.getByRole("list", { name: "Rule warnings" });
    expect(within(reasons).getByText(/pattern common in phishing/)).toBeInTheDocument();
    expect(within(reasons).queryByText(/Mentions paypal/)).toBeNull();
    expect(within(warnings).getByText(/Mentions paypal/)).toBeInTheDocument();
    expect(within(warnings).queryByText(/pattern common/)).toBeNull();
  });

  it("shows the headline, defanged host and advisory footer", () => {
    render(<ResultCard result={base} />);
    expect(screen.getByRole("heading", { name: "Suspicious: be careful" })).toBeInTheDocument();
    expect(screen.getByText("hxxp://paypal[.]com[.]evil[.]xyz")).toBeInTheDocument();
    expect(screen.getByText("PhishGuard is an advisory tool.")).toBeInTheDocument();
  });

  it("explains empty lists instead of hiding them", () => {
    render(<ResultCard result={{ ...base, model_reasons: [], rule_warnings: [] }} />);
    expect(screen.getByText("No rule warnings.")).toBeInTheDocument();
    expect(screen.getByText(/no specific reasons/)).toBeInTheDocument();
  });

  it("never shows a percentage or the word Safe", () => {
    const { container } = render(
      <ResultCard
        result={{
          ...base,
          band: "low",
          headline: "No strong phishing signs found",
          advice: "This is not a guarantee of safety.",
        }}
      />,
    );
    expect(container.textContent).not.toMatch(/%/);
    expect(container.textContent).not.toMatch(/\bsafe\b/i);
  });

  it("renders markup in reasons as plain text", () => {
    const evil = '<img src=x onerror="alert(1)">';
    const { container } = render(<ResultCard result={{ ...base, model_reasons: [evil] }} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(evil)).toBeInTheDocument();
  });
});
