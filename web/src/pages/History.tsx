import { useCallback, useEffect, useState } from "react";
import { api, type HistoryItem } from "../api";
import { BAND_LABELS, BAND_ORDER } from "../bands";

export default function History() {
  const [kind, setKind] = useState("");
  const [band, setBand] = useState("");
  const [items, setItems] = useState<HistoryItem[] | null>(null);
  const [error, setError] = useState("");
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(() => {
    api
      .history(kind, band)
      .then((data) => {
        setItems(data.items);
        setError("");
      })
      .catch((e: Error) => setError(e.message));
  }, [kind, band]);

  useEffect(load, [load]);

  async function deleteAll() {
    try {
      await api.deleteHistory();
      setConfirming(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <section>
      <h1>History</h1>
      <p>Only you can see this list. It keeps the defanged host, never the full link or email.</p>
      <div className="filters">
        <label>
          Type
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All</option>
            <option value="url">Link</option>
            <option value="email">Email</option>
          </select>
        </label>
        <label>
          Result
          <select value={band} onChange={(e) => setBand(e.target.value)}>
            <option value="">All</option>
            {BAND_ORDER.map((b) => (
              <option key={b} value={b}>
                {BAND_LABELS[b]}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && <p role="alert">{error}</p>}
      {items && items.length === 0 && <p>No checks yet.</p>}
      {items && items.length > 0 && (
        <table className="history">
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Host</th>
              <th>Result</th>
              <th>Model</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{new Date(item.created_at).toLocaleString()}</td>
                <td>{item.kind === "url" ? "Link" : "Email"}</td>
                <td className="host">{item.display_host}</td>
                <td className={`band-text band-${item.band}`}>{BAND_LABELS[item.band]}</td>
                <td>{item.model_version}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {confirming ? (
        <p>
          Delete your whole history? This cannot be undone.{" "}
          <button type="button" onClick={deleteAll}>
            Yes, delete everything
          </button>{" "}
          <button type="button" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </p>
      ) : (
        <button type="button" onClick={() => setConfirming(true)}>
          Delete all
        </button>
      )}
    </section>
  );
}
