import { api } from "../api";
import { href } from "../router";
import { Empty, ErrorState, Loading, ago, titleCase, useLoad } from "../ui";

const STATUS: Record<string, string> = {
  executed: "st-executed", pending_approval: "st-pending_approval", denied: "st-denied",
  failed: "st-failed", rolled_back: "st-rolled_back",
};

export default function Settings() {
  const c = useLoad(api.connectors);
  const d = c.data;
  return (
    <div className="page stack-24">
      <div className="page-head"><h1>Response</h1></div>
      {c.error ? <ErrorState error={c.error} retry={c.reload} /> : !d ? <Loading /> : (
        <>
          <div className={`callout ${d.live ? "callout-warn" : ""}`}>
            {d.live
              ? `Live: connectors change real systems. Auto-execution needs risk ${d.min_risk} or higher, a rollback path, and an action on the allowlist.`
              : `Dry Run: connectors change nothing. Set WARDEN_LIVE_ACTIONS=1 to go live. Auto-execution would need risk ${d.min_risk} or higher.`}
          </div>

          <section className="card card-flush">
            <div className="card-head"><h2>Action Routing</h2></div>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Action</th><th>Connector</th><th>Ready</th><th>Rollback</th><th>Automation</th>
                  <th className="right">Executed</th><th className="right">Approvals</th><th className="right">Failed</th>
                  <th className="right">Last Used</th></tr></thead>
                <tbody>{d.actions.map((a: any) => (
                  <tr key={a.action}>
                    <td style={{ fontWeight: 500 }}>{titleCase(a.action)}</td>
                    <td className="mono small">{a.connector}</td>
                    <td>{a.missing_config.length
                      ? <span className="pill st-failed" title={`Missing: ${a.missing_config.join(", ")}`}>Needs Config</span>
                      : <span className="pill st-executed">Yes</span>}</td>
                    <td>{a.can_rollback ? <span className="pill st-executed">Yes</span> : <span className="pill st-failed">No</span>}</td>
                    <td>{d.approval_only.includes(a.action) ? <span className="pill st-pending_approval">Analyst Only</span>
                      : a.auto && (a.can_rollback || ["notify", "create_ticket"].includes(a.action))
                        ? <span className="pill st-executed">Auto At {d.min_risk}+</span>
                        : <span className="pill">Analyst Only</span>}</td>
                    <td className="right num">{a.executed || 0}</td>
                    <td className="right num">{a.pending_approval || 0}</td>
                    <td className="right num">{a.failed ? <span className="sev-critical">{a.failed}</span> : 0}</td>
                    <td className="right small faint nowrap">{a.last_used ? ago(a.last_used) : "Never"}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </section>

          <section className="card card-flush">
            <div className="card-head"><h2>Recent Actions</h2></div>
            {d.recent.length === 0 ? <Empty title="No Actions Yet">Actions appear once cases recommend them.</Empty>
              : (
                <div className="table-wrap">
                  <table className="table">
                    <thead><tr><th>When</th><th>Case</th><th>Action</th><th>Target</th><th>Status</th><th>Detail</th></tr></thead>
                    <tbody>{d.recent.map((r: any, i: number) => (
                      <tr key={i}>
                        <td className="small faint nowrap">{ago(r.ts)}</td>
                        <td><a className="mono small" href={href(`case/${r.case}`)} title={r.title}>{r.case}</a></td>
                        <td className="nowrap">{titleCase(r.action)}</td>
                        <td className="mono small">{r.target}</td>
                        <td><span className={`pill ${STATUS[r.status] ?? ""}`}>{titleCase(r.status)}</span></td>
                        <td className="small faint">{r.detail}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              )}
          </section>

          <section className="card card-flush">
            <div className="card-head"><h2>Connectors</h2></div>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Connector</th><th>Actions</th><th>In Use</th></tr></thead>
                <tbody>{Object.entries(d.available).map(([n, acts]: [string, any]) => {
                  const used = d.actions.filter((a: any) => a.connector === n).map((a: any) => a.action);
                  return (
                    <tr key={n}>
                      <td className="mono small">{n}</td>
                      <td className="small">{acts.map((x: string) => titleCase(x)).join(", ")}</td>
                      <td>{used.length ? <span className="pill st-executed">{used.map(titleCase).join(", ")}</span>
                        : <span className="small faint">Not Mapped</span>}</td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
