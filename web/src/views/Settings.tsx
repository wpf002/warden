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
      <div className="page-head">
        <h1>Response</h1>
        {d && <span className={`pill ${d.live ? "st-pending_approval" : ""}`}>{d.live ? "Live" : "Dry Run"}</span>}
      </div>
      {c.error ? <ErrorState error={c.error} retry={c.reload} /> : !d ? <Loading /> : (
        <>
          <section className="card card-flush">
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Action</th><th>Connector</th><th>Automation</th>
                  <th className="right">Run</th><th className="right">Failed</th><th className="right">Last</th></tr></thead>
                <tbody>{d.actions.map((a: any) => (
                  <tr key={a.action}>
                    <td style={{ fontWeight: 500 }}>{titleCase(a.action)}</td>
                    <td className="mono small">{a.connector}
                      {a.missing_config.length > 0 &&
                        <span className="pill st-failed" style={{ marginLeft: 8 }} title={`Missing: ${a.missing_config.join(", ")}`}>Needs Config</span>}
                    </td>
                    <td>{d.approval_only.includes(a.action) || !a.auto || !(a.can_rollback || ["notify", "create_ticket"].includes(a.action))
                      ? <span className="pill st-pending_approval">Analyst</span>
                      : <span className="pill st-executed">Auto At {d.min_risk}+</span>}</td>
                    <td className="right num">{a.executed || 0}</td>
                    <td className="right num">{a.failed ? <span className="sev-critical">{a.failed}</span> : 0}</td>
                    <td className="right small faint nowrap">{a.last_used ? ago(a.last_used) : "Never"}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </section>

          <section className="card card-flush">
            <div className="card-head"><h2>Recent Actions</h2></div>
            {d.recent.length === 0 ? <Empty title="No Actions Yet">Actions appear once cases recommend them.</Empty> : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>When</th><th>Case</th><th>Action</th><th>Target</th><th>Status</th></tr></thead>
                  <tbody>{d.recent.slice(0, 8).map((r: any, i: number) => (
                    <tr key={i}>
                      <td className="small faint nowrap">{ago(r.ts)}</td>
                      <td><a className="mono small" href={href(`case/${r.case}`)} title={r.title}>{r.case}</a></td>
                      <td className="nowrap">{titleCase(r.action)}</td>
                      <td className="mono small">{r.target}</td>
                      <td><span className={`pill ${STATUS[r.status] ?? ""}`} title={r.detail}>{titleCase(r.status)}</span></td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
