import { Fragment } from "react";
import { api } from "../api";
import { ErrorState, Loading, titleCase, useLoad } from "../ui";

export default function Settings() {
  const c = useLoad(api.connectors);
  return (
    <div className="page-narrow stack-24">
      <h1>Response</h1>
      {c.error ? <ErrorState error={c.error} /> : !c.data ? <Loading /> : (
        <>
          <div className={`callout ${c.data.live ? "callout-warn" : ""}`}>
            {c.data.live ? "Live: connectors change real systems." : "Dry Run: connectors change nothing. Set WARDEN_LIVE_ACTIONS=1 to go live."}
          </div>
          <section className="card card-flush">
            <table className="table">
              <thead><tr><th>Action</th><th>Connector</th><th>Rollback</th><th>Automation</th></tr></thead>
              <tbody>{c.data.actions.map((a: any) => (
                <tr key={a.action}><td>{titleCase(a.action)}</td><td className="mono small">{a.connector}</td>
                  <td>{a.can_rollback ? <span className="pill st-executed">Yes</span> : <span className="pill">No</span>}</td>
                  <td>{a.action === "lock_user" ? <span className="pill st-pending_approval">Analyst Only</span>
                    : a.auto && (a.can_rollback || ["notify", "create_ticket"].includes(a.action)) ? <span className="pill st-executed">Auto Above Threshold</span>
                    : <span className="pill">No</span>}</td></tr>
              ))}</tbody>
            </table>
          </section>
          <section className="card"><h2>Connectors</h2>
            <dl className="kv small">{Object.entries(c.data.available).map(([n, acts]: [string, any]) => (
              <Fragment key={n}><dt className="mono">{n}</dt><dd>{acts.map((x: string) => titleCase(x)).join(", ")}</dd></Fragment>
            ))}</dl>
          </section>
        </>
      )}
    </div>
  );
}
