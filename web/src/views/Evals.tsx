import { useMemo, useRef, useState } from "react";
import { api } from "../api";
import { Empty, ErrorState, Loading, pretty, titleCase, useLoad } from "../ui";

type Run = { id: number; ts: string; suite: string; git_sha: string; analyzer: string; metrics: any };
const SERIES = [
  { key: "precision", label: "Correct Alerts", color: "var(--series-1)" },
  { key: "recall", label: "Attacks Caught", color: "var(--series-2)" },
  { key: "f1", label: "Overall", color: "var(--series-3)" },
];
const PER_PAGE = 15;

const pct = (v: number | null | undefined) => (v == null ? "-" : `${Math.round(Number(v) * 100)}%`);
const day = (ts: string) => new Date(ts).toLocaleDateString(undefined, { month: "long", day: "numeric" });

/** Brier is a 0-1 score where lower is better; say what it means instead of printing it. */
function calibration(b: number | null | undefined) {
  if (b == null) return { word: "-", hint: "Not measured" };
  if (b <= 0.08) return { word: "Accurate", hint: "Risk scores match what really happened" };
  if (b <= 0.15) return { word: "Close", hint: "Risk scores are roughly right" };
  return { word: "Off", hint: "Risk scores do not match reality" };
}

export default function Evals() {
  const h = useLoad<Run[]>(api.evalHistory);
  const [suite, setSuite] = useState("synthetic");
  const [page, setPage] = useState(0);
  const runs = useMemo(() => (h.data ?? []).filter((r) => r.suite === suite), [h.data, suite]);
  const last = runs[runs.length - 1];
  const m = last?.metrics;
  const ruleRows = useMemo(() => Object.entries(m?.per_rule ?? {}), [m]);
  const pages = Math.max(1, Math.ceil(ruleRows.length / PER_PAGE));
  const shown = ruleRows.slice(page * PER_PAGE, page * PER_PAGE + PER_PAGE);
  const cal = calibration(m?.brier);
  const missed = ruleRows.reduce((n, [, c]: [string, any]) => n + c.fn, 0);
  const falseAlarms = ruleRows.reduce((n, [, c]: [string, any]) => n + c.fp, 0);
  const caught = ruleRows.reduce((n, [, c]: [string, any]) => n + c.tp, 0);

  return (
    <div className="page stack-24">
      <div className="page-head" style={{ marginBottom: 0 }}>
        <h1>Evaluation</h1>
        <div className="tabs" role="tablist" aria-label="Suite">
          {["synthetic", "real"].map((s) => <button key={s} className="tab" role="tab" aria-selected={suite === s}
            onClick={() => { setSuite(s); setPage(0); }}>{titleCase(s)}</button>)}
        </div>
      </div>
      {h.error ? <ErrorState error={h.error} retry={h.reload} /> : !h.data ? <Loading rows={8} /> : runs.length === 0 ? (
        <div className="card"><Empty title="No Runs"><code>warden eval --record{suite === "real" ? " --real" : ""}</code></Empty></div>
      ) : (
        <>
          <div className="callout">
            On {day(last.ts)}, Warden caught <b>{caught}</b> of <b>{caught + missed}</b> known attacks
            with <b>{falseAlarms === 0 ? "no" : falseAlarms}</b> false alarm{falseAlarms === 1 ? "" : "s"},
            and agreed with the analyst on {pct(m.action_agreement)} of response decisions.
          </div>
          <section className="kpis" style={{ marginBottom: 0, gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }}>
            <div className="kpi"><div className="label">Attacks Caught</div><div className="value">{pct(m.overall.recall)}</div>
              <div className="hint">{caught} of {caught + missed} known attacks</div></div>
            <div className="kpi"><div className="label">Correct Alerts</div><div className="value">{pct(m.overall.precision)}</div>
              <div className="hint">{falseAlarms === 0 ? "No false alarms" : `${falseAlarms} false alarms`}</div></div>
            <div className="kpi"><div className="label">Risk Scores</div><div className="value">{cal.word}</div>
              <div className="hint">{cal.hint}</div></div>
            <div className="kpi"><div className="label">Agreed With Analyst</div><div className="value">{pct(m.action_agreement)}</div>
              <div className="hint">On which action to take</div></div>
            <div className="kpi"><div className="label">Right Playbook Found</div><div className="value">{pct(m.retrieval_hit_rate)}</div>
              <div className="hint">Playbook in the top 3 retrieved</div></div>
          </section>
          {runs.length > 1 && (
            <div className="grid-2">
              <section className="card"><h2>Accuracy Over Time</h2>
                <LineChart runs={runs} series={SERIES} domain={[0, 1]} /></section>
              <section className="card"><h2>Risk Score Accuracy</h2>
                <LineChart runs={runs} series={[{ key: "brier", label: "Brier", color: "var(--series-1)" }]} domain={[0, 0.3]} single /></section>
            </div>
          )}
          <section className="card card-flush">
            <div className="card-head">
              <h2>By Rule</h2>
              <span className="small faint">{day(last.ts)} · {last.analyzer}</span>
            </div>
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Rule</th><th className="right">Caught</th><th className="right">False Alarms</th>
                <th className="right">Missed</th><th className="right">Correct Alerts</th><th className="right">Attacks Caught</th></tr></thead>
              <tbody>{shown.map(([r, c]: [string, any]) => (
                <tr key={r}>
                  <td>{pretty(r)}</td>
                  <td className="right num">{c.tp}</td>
                  <td className="right num">{c.fp ? <span className="sev-critical">{c.fp}</span> : 0}</td>
                  <td className="right num">{c.fn ? <span className="sev-high">{c.fn}</span> : 0}</td>
                  <td className="right num">{pct(c.precision)}</td>
                  <td className="right num">{pct(c.recall)}</td>
                </tr>
              ))}</tbody>
            </table></div>
            {ruleRows.length > PER_PAGE && (
              <div className="card-head" style={{ borderTop: "1px solid var(--border)", borderBottom: "none" }}>
                <span className="small faint">{page * PER_PAGE + 1}-{Math.min(ruleRows.length, (page + 1) * PER_PAGE)} of {ruleRows.length}</span>
                <div className="row">
                  <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
                  <span className="small faint">Page {page + 1} of {pages}</span>
                  <button className="btn btn-ghost btn-sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
                </div>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function val(r: Run, key: string): number | null {
  const m = r.metrics;
  const v = key === "brier" ? m.brier : m.overall?.[key];
  return v == null ? null : Number(v);
}

/** One y-axis, 2px lines, >=8px markers, crosshair tooltip, legend plus direct labels. */
function LineChart({ runs, series, domain, single }: { runs: Run[]; series: typeof SERIES; domain: [number, number]; single?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const W = 560, H = 220, L = 40, R = 72, T = 12, B = 28;
  const x = (i: number) => L + (runs.length === 1 ? (W - L - R) / 2 : (i / (runs.length - 1)) * (W - L - R));
  const y = (v: number) => T + (1 - (v - domain[0]) / (domain[1] - domain[0])) * (H - T - B);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((t) => domain[0] + t * (domain[1] - domain[0]));
  return (
    <div ref={ref} style={{ position: "relative" }}>
      {!single && <div className="legend" style={{ marginBottom: 8 }}>{series.map((s) => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}</div>}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={`${series.map((s) => s.label).join(", ")} across ${runs.length} runs`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const px = ((e.clientX - r.left) / r.width) * W;
          let best = 0;
          runs.forEach((_, i) => { if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i; });
          setHover(best);
        }}>
        {ticks.map((t) => (
          <g key={t}><line x1={L} x2={W - R} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeWidth={1} />
            <text x={L - 8} y={y(t) + 4} textAnchor="end" fontSize="12" fill="var(--text-faint)">{t.toFixed(2)}</text></g>
        ))}
        {hover != null && <line x1={x(hover)} x2={x(hover)} y1={T} y2={H - B} stroke="var(--border-strong)" strokeWidth={1} />}
        {series.map((s, si) => {
          const pts = runs.map((r, i) => [i, val(r, s.key)] as const).filter(([, v]) => v != null) as [number, number][];
          const last = pts[pts.length - 1];
          // direct-label only when no other series ends within 6% of the range; the legend covers the rest
          const ends = series.map((o) => val(runs[runs.length - 1], o.key));
          const clear = last && ends.every((v, oi) => oi === si || v == null || Math.abs(v - last[1]) > 0.06 * (domain[1] - domain[0]));
          return (
            <g key={s.key}>
              <polyline points={pts.map(([i, v]) => `${x(i)},${y(v)}`).join(" ")} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" />
              {pts.map(([i, v]) => <circle key={i} cx={x(i)} cy={y(v)} r={hover === i ? 5 : 4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />)}
              {last && !single && clear && <text x={x(last[0]) + 10} y={y(last[1]) + 4} fontSize="12" fill="var(--text-muted)">{s.label}</text>}
            </g>
          );
        })}
        <text x={L} y={H - 8} fontSize="12" fill="var(--text-faint)">Oldest</text>
        <text x={W - R} y={H - 8} fontSize="12" fill="var(--text-faint)" textAnchor="end">Latest</text>
      </svg>
      {hover != null && (
        <div className="chart-tip" style={{ left: `${(x(hover) / W) * 100}%`, top: 24, transform: "translateX(-50%)" }}>
          <div className="faint">{new Date(runs[hover].ts).toISOString().slice(0, 16).replace("T", " ")} · {runs[hover].git_sha?.slice(0, 7)}</div>
          {series.map((s) => <div key={s.key} className="num">{s.label}: {val(runs[hover], s.key)?.toFixed(3) ?? "-"}</div>)}
        </div>
      )}
    </div>
  );
}
