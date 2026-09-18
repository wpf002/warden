import { useState } from "react";
import { api, type Me } from "../api";
import { href } from "../router";
import { Button, Empty, ErrorState, Loading, ago, pretty, titleCase, toast, useLoad } from "../ui";

const STATUS: Record<string, [string, string]> = {
  requested: ["Requested", ""], generated: ["Generated", ""], rejected_static: ["Failed Checks", "st-failed"],
  failed_eval: ["Failed Eval", "st-failed"], ready_for_review: ["Ready for Review", "st-pending_approval"],
  rejected: ["Rejected", ""], approved: ["Approved", "st-executed"], pr_opened: ["PR Opened", "st-executed"],
};
const Status = ({ s }: { s: string }) => <span className={`pill ${STATUS[s]?.[1] ?? ""}`}>{STATUS[s]?.[0] ?? s}</span>;

export default function Proposals({ id, user }: { id?: string; user: Me }) {
  return id ? <Detail id={id} user={user} /> : <List />;
}

function List() {
  const l = useLoad(api.proposals);
  return (
    <div className="page">
      <div className="page-head"><h1>Proposals</h1></div>
      <div className="card card-flush">
        {l.error ? <div style={{ padding: 16 }}><ErrorState error={l.error} retry={l.reload} /></div>
          : !l.data ? <div style={{ padding: 16 }}><Loading /></div>
          : l.data.length === 0 ? <Empty title="No Proposals"><code>warden propose --gaps</code></Empty>
          : (
            <table className="table">
              <thead><tr><th>Proposal</th><th>Rule</th><th>Trigger</th><th>Status</th><th className="right">Created</th></tr></thead>
              <tbody>{l.data.map((p) => (
                <tr key={p.id} className="clickable" onClick={() => { location.hash = `#/proposals/${p.id}`; }}>
                  <td className="mono">{p.id}</td><td>{p.rule_id ? pretty(p.rule_id) : <span className="faint">Pending</span>}</td>
                  <td className="small muted">{titleCase(p.trigger ?? "")} <span className="faint">{p.source}</span></td>
                  <td><Status s={p.status} /></td><td className="right small faint">{ago(p.created)}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
      </div>
    </div>
  );
}

function Detail({ id, user }: { id: string; user: Me }) {
  const p = useLoad(() => api.proposal(id), [id]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  if (p.error) return <div className="page-narrow"><ErrorState error={p.error} /></div>;
  if (!p.data) return <div className="page"><Loading rows={10} /></div>;
  const x = p.data, ev = x.eval ?? {};
  async function review(decision: string) {
    setBusy(decision);
    try { const r = await api.review(id, decision, note); toast(r.pr ? `PR opened: ${r.pr}` : `Proposal ${r.status}`); p.reload(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(null); }
  }
  const suite = (name: string) => ev[name] ? (
    <tr><td>{titleCase(name)}</td><td className="num">{ev[name].overall?.precision}</td><td className="num">{ev[name].overall?.recall}</td>
      <td className="mono small">{ev[name].rule ? `${ev[name].rule.tp} / ${ev[name].rule.fp} / ${ev[name].rule.fn}` : "-"}</td></tr>) : null;
  return (
    <div className="page">
      <p style={{ margin: "0 0 16px" }}><a href={href("proposals")} className="small">&larr; Proposals</a></p>
      <div className="page-head"><div>
        <div className="row-wrap" style={{ marginBottom: 8 }}><Status s={x.status} /><span className="small faint mono">{x.id}</span></div>
        <h1>{x.rule_id ? pretty(x.rule_id) : "Proposal"}</h1>
        <div className="small faint">{titleCase(x.trigger ?? "")} · {x.source} · {x.model}{x.cost_usd != null && ` · $${x.cost_usd.toFixed(3)}`}</div>
      </div>
        {x.pr_url && <a className="btn" href={x.pr_url} target="_blank" rel="noreferrer">View PR</a>}
      </div>
      <div className="grid-main">
        <div className="stack-24">
          {x.rationale && <section className="card"><h2>Rationale</h2><p className="summary" style={{ margin: 0 }}>{x.rationale}</p></section>}
          {(x.checks?.static ?? []).length > 0 && (
            <div className="callout callout-danger"><strong>Static checks failed</strong><ul>{x.checks.static.map((s: string) => <li key={s}>{s}</li>)}</ul></div>)}
          <section className="card card-flush">
            <div className="card-head"><h2>Sandbox Eval</h2>
              <span className={`pill ${ev.test?.ok ? "st-executed" : "st-failed"}`}>{ev.test ? (ev.test.ok ? "Test Passed" : "Test Failed") : "Not Run"}</span></div>
            <table className="table"><thead><tr><th>Suite</th><th>Precision</th><th>Recall</th><th>Rule TP / FP / FN</th></tr></thead>
              <tbody>{suite("synthetic")}{suite("real")}</tbody></table>
            <details style={{ padding: "12px 16px", borderTop: "1px solid var(--border)" }}>
              <summary>Historical Hits ({(ev.historical_hits ?? []).length})</summary>
              <ul className="small">{(ev.historical_hits ?? []).map((h: any, i: number) => <li key={i}><span className="mono">{h.file}</span>: {h.title ?? h.error}</li>)}</ul>
            </details>
            {ev.test && !ev.test.ok && <pre className="code" style={{ margin: 16 }}>{ev.test.output}</pre>}
          </section>
          {Object.entries(x.files ?? {}).map(([path, body]) => (
            <section key={path} className="card"><h3 className="mono" style={{ textTransform: "none", letterSpacing: 0 }}>{path}</h3>
              <pre className="code">{String(body)}</pre></section>
          ))}
        </div>
        <aside className="stack-16">
          {x.status === "ready_for_review" && user.role === "admin" ? (
            <section className="card stack-16">
              <h2 style={{ margin: 0 }}>Review</h2>
              <textarea className="input" rows={3} placeholder="Note" value={note} onChange={(e) => setNote(e.target.value)} />
              <Button className="btn-primary" busy={busy === "approve"} disabled={!!busy} onClick={() => review("approve")}>Approve & Open PR</Button>
              <Button className="btn-danger" busy={busy === "reject"} disabled={!!busy} onClick={() => review("reject")}>Reject</Button>
            </section>
          ) : x.review ? <section className="card small"><h2>Review</h2>{x.review.by}: {x.review.note || "-"}</section> : null}
        </aside>
      </div>
    </div>
  );
}
