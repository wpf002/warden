import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { href } from "../router";
import { Empty, ErrorState, Loading, RateBar, Sparkline, ago, pretty, useLoad } from "../ui";

const DOMAINS = ["all", "identity", "endpoint", "network", "cloud", "anomaly"];
const PER_PAGE = 15;

export default function Detections() {
  const [view, setView] = useState("rules");
  const d = useLoad(api.detections);
  const [dom, setDom] = useState("all");
  const [page, setPage] = useState(0);
  const rows = useMemo(() => (d.data ?? []).filter((x) => dom === "all" || x.domain === dom), [d.data, dom]);
  const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
  useEffect(() => { setPage(0); }, [dom]);
  const shown = rows.slice(page * PER_PAGE, page * PER_PAGE + PER_PAGE);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const x of d.data ?? []) c[x.domain] = (c[x.domain] ?? 0) + 1;
    return c;
  }, [d.data]);
  return (
    <div className="page">
      <div className="page-head">
        <h1>Detections</h1>
        <div className="tabs" role="tablist" aria-label="View">
          <button className="tab" role="tab" aria-selected={view === "rules"} onClick={() => setView("rules")}>Rules</button>
          <button className="tab" role="tab" aria-selected={view === "coverage"} onClick={() => setView("coverage")}>ATT&amp;CK Coverage</button>
        </div>
      </div>
      {view === "coverage" && <Coverage />}
      {view === "coverage" ? null : (<>
      <div className="toolbar">
        <div className="tabs" role="tablist" aria-label="Domain">
          {DOMAINS.map((k) => (
            <button key={k} className="tab" role="tab" aria-selected={dom === k} onClick={() => setDom(k)}>
              {k[0].toUpperCase() + k.slice(1)} <span className="num faint">{k === "all" ? d.data?.length ?? "" : counts[k] ?? 0}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="card card-flush">
        {d.error ? <div style={{ padding: 16 }}><ErrorState error={d.error} retry={d.reload} /></div>
          : !d.data ? <div style={{ padding: 16 }}><Loading rows={10} /></div>
          : rows.length === 0 ? <Empty title="No Detections" />
          : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Rule</th><th>ATT&amp;CK</th><th className="right">Fired</th><th className="right">TP</th>
                  <th className="right">FP</th><th>FP Rate</th><th>Threshold</th><th>8-Week Trend</th><th className="right">Last Fired</th></tr></thead>
                <tbody>{shown.map((x) => (
                  <tr key={x.id}>
                    <td style={{ maxWidth: 320 }}>
                      <a href={href(`knowledge/${x.playbook}`)} style={{ fontWeight: 500, color: "var(--text)" }} title={x.name}>{pretty(x.id)}</a>

                    </td>
                    <td><div className="row-wrap">{x.mitre.length ? x.mitre.map((t: string) => <span key={t} className="tag">{t}</span>)
                      : <span className="small faint">Per Case</span>}</div></td>
                    <td className="right num">{x.fired}</td>
                    <td className="right num">{x.tp}</td>
                    <td className="right num">{x.fp}</td>
                    <td><RateBar value={x.fp_rate} /></td>
                    <td className="small">{x.threshold_bump ? <span className="pill sev-medium">+{x.threshold_bump}</span> : <span className="faint">Default</span>}</td>
                    <td>{x.weekly.length ? <Sparkline values={x.weekly.map((w: any) => w.fired)} label={`${x.id} weekly fires`} /> : <span className="faint small">-</span>}</td>
                    <td className="right small faint nowrap">{x.last_fired ? ago(x.last_fired) : "Never"}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        {rows.length > PER_PAGE && (
          <div className="card-head" style={{ borderTop: "1px solid var(--border)", borderBottom: "none" }}>
            <span className="small faint">
              {page * PER_PAGE + 1}-{Math.min(rows.length, (page + 1) * PER_PAGE)} of {rows.length}
            </span>
            <div className="row">
              <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
              <span className="small faint">Page {page + 1} of {pages}</span>
              <button className="btn btn-ghost btn-sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </div>
        )}
      </div>
      </>)}
    </div>
  );
}

// Coverage against TDL, the Threat Detection Library: which of its ATT&CK techniques Warden covers.
function Coverage() {
  const c = useLoad(api.coverage);
  const [only, setOnly] = useState("gaps");
  if (c.error) return <ErrorState error={c.error} retry={c.reload} />;
  if (!c.data) return <Loading rows={8} />;
  if (!c.data.available) {
    return <Empty title="No Coverage Index">Run <span className="mono">python scripts/sync_tdl.py</span> to build it from the TDL library.</Empty>;
  }
  const d = c.data;
  const pct = Math.round((d.covered / Math.max(1, d.techniques - d.revoked)) * 100);
  const techs = (d.techniques_detail ?? []).filter((t: any) =>
    only === "all" ? true : only === "gaps" ? !t.covered && !t.revoked : t.covered);
  return (
    <div className="stack-24">
      <div className="kpis">
        <div className="kpi"><div className="label">Techniques Covered</div><div className="value">{d.covered} of {d.techniques - d.revoked}</div><div className="hint">{pct}% of the TDL library</div></div>
        <div className="kpi"><div className="label">Gaps</div><div className="value">{d.gaps.length}</div><div className="hint">TDL detects these, Warden does not</div></div>
        <div className="kpi"><div className="label">TDL Rules</div><div className="value">{d.rules}</div><div className="hint">Source of the mapping</div></div>
      </div>
      <section className="card card-flush">
        <div className="card-head"><h2>By Tactic</h2></div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Tactic</th><th className="right">Covered</th><th className="right">Techniques</th><th>Coverage</th><th className="right">TDL Rules</th></tr></thead>
            <tbody>{d.tactics.map((t: any) => (
              <tr key={t.tactic}>
                <td style={{ fontWeight: 500 }}>{t.tactic}</td>
                <td className="right num">{t.covered}</td>
                <td className="right num">{t.techniques - t.revoked}</td>
                <td style={{ width: 200 }}><RateBar value={t.covered / Math.max(1, t.techniques - t.revoked)} /></td>
                <td className="right num">{t.tdl_rules}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </section>
      <section className="card card-flush">
        <div className="card-head">
          <h2>Techniques</h2>
          <div className="tabs" role="tablist" aria-label="Filter">
            {["gaps", "covered", "all"].map((k) => (
              <button key={k} className="tab" role="tab" aria-selected={only === k} onClick={() => setOnly(k)}>
                {k[0].toUpperCase() + k.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th className="right">TDL Rules</th><th>Warden</th></tr></thead>
            <tbody>{techs.slice(0, 60).map((t: any) => (
              <tr key={t.technique}>
                <td className="mono small">{t.technique}</td>
                <td>{t.name}</td>
                <td className="small faint">{t.tactic}</td>
                <td className="right num">{t.tdl_rules}</td>
                <td>{t.covered ? <div className="row-wrap">{t.detections.map((x: string) => <span key={x} className="tag">{pretty(x)}</span>)}</div>
                  : <span className="pill st-failed">Gap</span>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
