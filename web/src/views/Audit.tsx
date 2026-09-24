import { Fragment, useMemo, useState } from "react";
import { api } from "../api";
import { href } from "../router";
import { Empty, ErrorState, Loading, ago, fmtTime, titleCase, useLoad } from "../ui";

const PER_PAGE = 25;
const TABS: [string, string][] = [["people", "Analyst"], ["system", "System"], ["all", "All"]];
const TONE: Record<string, string> = {
  approve_action: "st-executed", execute_action: "st-executed", verdict: "st-executed",
  deny_action: "st-denied", rollback_action: "st-rolled_back", expire_exclusion: "st-rolled_back",
  add_exclusion: "st-pending_approval", propose: "st-pending_approval",
};

export default function Audit() {
  const a = useLoad(api.audit);
  const ex = useLoad(api.exclusions);
  const [tab, setTab] = useState("people");
  const [page, setPage] = useState(0);

  const rows = useMemo(() => (a.data ?? []).filter((r: any) =>
    tab === "all" || (tab === "system" ? r.actor === "system" : r.actor !== "system")), [a.data, tab]);
  const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
  const shown = rows.slice(page * PER_PAGE, page * PER_PAGE + PER_PAGE);
  const days = useMemo(() => {                       // day headers keep a long log readable
    const out: Record<string, any[]> = {};
    for (const r of shown) (out[String(r.ts).slice(0, 10)] ??= []).push(r);
    return Object.entries(out);
  }, [shown]);

  return (
    <div className="page stack-24">
      <div className="page-head" style={{ marginBottom: 0 }}>
        <h1>Audit Log</h1>
        <div className="tabs" role="tablist" aria-label="Actor">
          {TABS.map(([k, l]) => (
            <button key={k} className="tab" role="tab" aria-selected={tab === k}
              onClick={() => { setTab(k); setPage(0); }}>{l}</button>
          ))}
        </div>
      </div>

      {ex.data && ex.data.length > 0 && (
        <section className="card card-flush">
          <div className="card-head"><h2>Active Exclusions</h2><span className="small faint">{ex.data.length}</span></div>
          <table className="table">
            <thead><tr><th>Rule</th><th>Entity</th><th>Reason</th><th>By</th><th className="right">Hits</th><th>Expires</th><th /></tr></thead>
            <tbody>{ex.data.map((e: any) => (
              <tr key={e.id}>
                <td>{titleCase(e.rule)}</td><td className="mono small">{e.field}={e.value}</td>
                <td>{titleCase(e.reason)}</td><td className="small">{e.created_by}</td>
                <td className="right num">{e.hits}</td><td className="small faint">{String(e.expires).slice(0, 10)}</td>
                <td className="right"><button className="btn btn-sm btn-ghost"
                  onClick={async () => { await api.expire(e.id); ex.reload(); a.reload(); }}>Expire</button></td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      )}

      <section className="card card-flush">
        {a.error ? <div style={{ padding: 16 }}><ErrorState error={a.error} retry={a.reload} /></div>
          : !a.data ? <div style={{ padding: 16 }}><Loading rows={8} /></div>
          : shown.length === 0 ? <Empty title="No Entries">Approvals, rollbacks and verdicts land here.</Empty>
          : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th style={{ width: 96 }}>When</th><th style={{ width: 120 }}>Who</th>
                  <th style={{ width: 150 }}>Action</th><th style={{ width: 150 }}>Target</th><th>Detail</th></tr></thead>
                <tbody>{days.map(([day, list]) => (
                  <Fragment key={day}>
                    <tr className="row-group"><td colSpan={5} className="small faint">{day}</td></tr>
                    {list.map((r: any) => (
                      <tr key={r.id}>
                        <td className="small faint nowrap" title={fmtTime(r.ts, true)}>{ago(r.ts)}</td>
                        <td className="small">{r.actor === "system" ? <span className="faint">System</span> : r.actor}</td>
                        <td><span className={`pill ${TONE[r.action] ?? ""}`}>{titleCase(r.action)}</span></td>
                        <td className="mono small">{/^(ALT|INC)-/.test(r.target) ? <a href={href(`case/${r.target}`)}>{r.target}</a>
                          : /^PROP-/.test(r.target) ? <a href={href(`proposals/${r.target}`)}>{r.target}</a>
                          : <span className="faint">{r.target}</span>}</td>
                        <td className="small muted">{detail(r.detail)}</td>
                      </tr>
                    ))}
                  </Fragment>
                ))}</tbody>
              </table>
            </div>
          )}
        {rows.length > PER_PAGE && (
          <div className="card-head" style={{ borderTop: "1px solid var(--border)", borderBottom: "none" }}>
            <span className="small faint">{page * PER_PAGE + 1}-{Math.min(rows.length, (page + 1) * PER_PAGE)} of {rows.length}</span>
            <div className="row">
              <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
              <span className="small faint">Page {page + 1} of {pages}</span>
              <button className="btn btn-ghost btn-sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function detail(d: Record<string, unknown> | null) {
  const parts = Object.entries(d ?? {}).filter(([, v]) => v !== "" && v !== null && v !== false && v !== 0);
  if (parts.length === 0) return <span className="faint">-</span>;
  return (
    <span className="row-wrap">
      {parts.map(([k, v]) => (
        <span key={k} className="small"><span className="faint">{titleCase(k)}</span>{" "}
          {typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
      ))}
    </span>
  );
}
