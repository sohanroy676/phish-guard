import type { AnalysisResult } from "../api";

export default function ResultCard({ result }: { result: AnalysisResult }) {
  return (
    <section className={`result band-${result.band}`} aria-label="Result">
      <h2>{result.headline}</h2>
      <p className="host">{result.display_host}</p>
      <p>{result.advice}</p>

      <h3>Why the model thinks so</h3>
      {result.model_reasons.length > 0 ? (
        <ul aria-label="Model reasons">
          {result.model_reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : (
        <p>The model has no specific reasons to show.</p>
      )}

      <h3>Rule warnings</h3>
      {result.rule_warnings.length > 0 ? (
        <ul aria-label="Rule warnings">
          {result.rule_warnings.map((warning) => (
            <li key={warning.rule_id}>{warning.message}</li>
          ))}
        </ul>
      ) : (
        <p>No rule warnings.</p>
      )}

      <p className="footer">{result.footer}</p>
    </section>
  );
}
