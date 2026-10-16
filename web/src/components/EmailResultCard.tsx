import type { EmailResult } from "../api";
import ResultCard from "./ResultCard";

// Everything below is rendered as React text nodes. Email content is never parsed as HTML.
export default function EmailResultCard({ result }: { result: EmailResult }) {
  const card = { ...result, display_host: `Sender: ${result.sender}` };
  return (
    <div className="email-result">
      <ResultCard result={card} />

      <section aria-label="Header checks">
        <h3>Header checks</h3>
        <p>{result.header_checks.message}</p>
        {result.header_checks.warnings.length > 0 && (
          <ul aria-label="Header warnings">
            {result.header_checks.warnings.map((warning) => (
              <li key={warning.rule_id}>{warning.message}</li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Links">
        <h3>Links in this email</h3>
        {!result.links_checked && (
          <p>Links were not checked because the URL model is not loaded.</p>
        )}
        {result.links_checked && result.links.length === 0 && <p>No web links found.</p>}
        {result.links.length > 0 && (
          <ul aria-label="Link results">
            {result.links.map((link, i) => (
              <li key={`${link.display_host}-${i}`} className={`band-${link.band}`}>
                <span className="host">{link.display_host}</span>: {link.headline}
                {link.lookalike && (
                  <strong> Lookalike link: its text names a different site.</strong>
                )}
                {link.rule_warnings.length > 0 && (
                  <ul>
                    {link.rule_warnings.map((warning) => (
                      <li key={warning.rule_id}>{warning.message}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
        {result.truncated && <p>This email was very long, so only part of it was checked.</p>}
      </section>

      <p className="note">{result.model_note}</p>
    </div>
  );
}
