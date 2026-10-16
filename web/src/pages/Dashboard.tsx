import { useCallback, useEffect, useState } from "react";
import { Bar, BarChart, Tooltip, XAxis, YAxis } from "recharts";
import { api, type DashboardSummary } from "../api";
import { BAND_LABELS, BAND_ORDER } from "../bands";

export default function Dashboard() {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState("");
  const [live, setLive] = useState(false);

  const load = useCallback(() => {
    api
      .dashboardSummary()
      .then((summary) => {
        setData(summary);
        setError("");
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
    const source = new EventSource("/api/events");
    source.addEventListener("analysis", load);
    source.onopen = () => setLive(true);
    source.onerror = () => setLive(false); // the browser reconnects by itself
    return () => source.close();
  }, [load]);

  if (error) return <p role="alert">{error}</p>;
  if (!data) return <p>Loading…</p>;

  return (
    <section>
      <h1>Dashboard</h1>
      <p>{live ? "Live: updates as you check things." : "Reconnecting for live updates…"}</p>
      <div className="cards">
        <div className="card">
          <strong>{data.total}</strong> checks
        </div>
        <div className="card">
          <strong>{data.by_kind.url}</strong> links
        </div>
        <div className="card">
          <strong>{data.by_kind.email}</strong> emails
        </div>
      </div>
      <h2>Results</h2>
      <ul className="bands">
        {BAND_ORDER.map((b) => (
          <li key={b} className={`band-text band-${b}`}>
            {BAND_LABELS[b]}: {data.by_band[b]}
          </li>
        ))}
      </ul>
      <h2>Last 30 days</h2>
      <BarChart width={640} height={200} data={data.trend}>
        <XAxis dataKey="date" tickFormatter={(d: string) => d.slice(5)} interval={4} />
        <YAxis allowDecimals={false} width={30} />
        <Tooltip />
        <Bar dataKey="count" name="Checks" fill="#555" isAnimationActive={false} />
      </BarChart>
      <h2>Recent warnings</h2>
      {data.recent_high_risk.length === 0 ? (
        <p>None yet.</p>
      ) : (
        <ul>
          {data.recent_high_risk.map((item) => (
            <li key={item.id}>
              <span className="host">{item.display_host}</span> —{" "}
              <span className={`band-text band-${item.band}`}>{BAND_LABELS[item.band]}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
