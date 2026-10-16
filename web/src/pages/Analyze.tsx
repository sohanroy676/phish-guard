import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import type { AnalysisResult } from "../api";
import ResultCard from "../components/ResultCard";

export default function Analyze() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(await api.analyzeUrl(url));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Analyze</h1>
      <p>Paste a link to check. PhishGuard never opens it.</p>
      <form onSubmit={submit}>
        <label htmlFor="url">Link</label>
        <input
          id="url"
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <button type="submit" disabled={busy || url.trim() === ""}>
          {busy ? "Checking…" : "Check link"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {result && <ResultCard result={result} />}
    </section>
  );
}
