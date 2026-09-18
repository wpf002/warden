import { api } from "../api";
import { href } from "../router";
import { Empty, ErrorState, Loading, fmtTime, titleCase, useLoad } from "../ui";

export default function Audit() {
  const a = useLoad(api.audit);
  const ex = useLoad(api.exclusions);
  return (
    <div className="page stack-24">
      <div className="page-head" style={{ marginBottom: 0 }}><h1>Audit Log</h1></div>
      <section className="card card-flush">
        <div className="card-head"><h2>Active Exclusions</h2></div>
        {ex.error ? <div style={{ padding: 16 }}><ErrorState error={ex.error} /></div> : !ex.data ? <div style={{ padding: 16 }}><Loading rows={2} /></div>
          : ex.data.length === 0 ? <Empty title="None" />
          : <table className="table"><thead><tr><th>#</th><th>Rule</th><th>Entity</th><th>Reason</th><th>By</th><th className="right">Hits</th><th>Expires</th><th /></tr></thead>
              <tbody>{ex.data.map((e) => (
                <tr key={e.id}><td className="num">{e.id}</td><td>{e.rule}</td><td className="mono small">{e.field}={e.value}</td><td>{titleCase(e.reason)}</td>
                  <td className="small">{e.created_by}</td><td className="right num">{e.hits}</td><td className="small faint">{String(e.expires).slice(0, 10)}</td>
                  <td className="right"><button className="btn btn-sm btn-ghost" onClick={async () => { await api.expire(e.id); ex.reload(); a.reload(); }}>Expire</button></td></tr>
              ))}</tbody></table>}
      </section>
      <section className="card card-flush">
        {a.error ? <div style={{ padding: 16 }}><ErrorState error={a.error} retry={a.reload} /></div>
          : !a.data ? <div style={{ padding: 16 }}><Loading rows={8} /></div>
          : a.data.length === 0 ? <Empty title="No Entries" />
          : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>When (UTC)</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
              <tbody>{a.data.map((r) => (
                <tr key={r.id}>
                  <td className="mono small nowrap">{fmtTime(r.ts, true)}</td><td>{r.actor}</td>
                  <td><span className="tag">{titleCase(r.action)}</span></td>
                  <td className="mono small">{/^(ALT|INC)-/.test(r.target) ? <a href={href(`case/${r.target}`)}>{r.target}</a>
                    : /^PROP-/.test(r.target) ? <a href={href(`proposals/${r.target}`)}>{r.target}</a> : r.target}</td>
                  <td className="small muted" style={{ maxWidth: 480 }}>
                    {Object.entries(r.detail ?? {}).filter(([, v]) => v !== "" && v !== null && v !== false)
                      .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ")}
                  </td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
      </section>
    </div>
  );
}
