import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { EmailResult } from "../api";
import EmailResultCard from "../components/EmailResultCard";

type Tab = "fields" | "source" | "file";
const TABS: { id: Tab; label: string }[] = [
  { id: "fields", label: "Fields" },
  { id: "source", label: "Paste original" },
  { id: "file", label: "Upload .eml" },
];

export default function AnalyzeEmail() {
  const [tab, setTab] = useState<Tab>("fields");
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [body, setBody] = useState("");
  const [source, setSource] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<EmailResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const ready =
    tab === "fields"
      ? subject.trim() !== "" || body.trim() !== ""
      : tab === "source"
        ? source.trim() !== ""
        : file !== null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      if (tab === "fields") setResult(await api.analyzeEmailFields(subject, sender, body));
      else if (tab === "source") setResult(await api.analyzeEmailSource(source));
      else if (file) setResult(await api.analyzeEmailFile(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Analyze an email</h1>
      <p>PhishGuard reads the email here and never opens its links.</p>
      <p>
        <Link to="/analyze">Check a single link instead</Link>
      </p>
      <div role="tablist" aria-label="Email input">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls="email-panel"
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <form onSubmit={submit} role="tabpanel" id="email-panel" aria-labelledby={`tab-${tab}`}>
        {tab === "fields" && (
          <>
            <label htmlFor="subject">Subject</label>
            <input
              id="subject"
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
            />
            <label htmlFor="sender">Sender</label>
            <input
              id="sender"
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              autoComplete="off"
            />
            <label htmlFor="body">Body</label>
            <textarea id="body" rows={10} value={body} onChange={(e) => setBody(e.target.value)} />
            <p>Header checks need the original email. Use the other tabs for them.</p>
          </>
        )}
        {tab === "source" && (
          <>
            <label htmlFor="source">Original email source</label>
            <textarea
              id="source"
              rows={14}
              value={source}
              onChange={(e) => setSource(e.target.value)}
            />
          </>
        )}
        {tab === "file" && (
          <>
            <label htmlFor="eml">Email file (.eml, up to 2 MB)</label>
            <input
              id="eml"
              type="file"
              accept=".eml,message/rfc822"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </>
        )}
        <button type="submit" disabled={busy || !ready}>
          {busy ? "Checking…" : "Check email"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {result && <EmailResultCard result={result} />}
    </section>
  );
}
