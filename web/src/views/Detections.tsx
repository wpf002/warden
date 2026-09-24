import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { href } from "../router";
import { Empty, ErrorState, Loading, RateBar, Sparkline, ago, pretty, useLoad } from "../ui";

const DOMAINS = ["all", "identity", "endpoint", "network", "cloud", "anomaly"];
const PER_PAGE = 15;

export default function Detections() {
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
      </div>
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
    </div>
  );
}
