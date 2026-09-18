import { useEffect, useMemo, useRef, useState } from "react";
import { api, type CaseSummary, type Me } from "../api";
import { go } from "../router";
import { Button, CaseStatus, Empty, ErrorState, Loading, Risk, SeverityPill, ago, memo, pretty, title, toast, useKeys, useLoad } from "../ui";

const TABS: [string, string][] = [["active", "Active"], ["awaiting_approval", "Needs Approval"], ["closed", "Closed"], ["all", "All"]];
const SEVS = ["critical", "high", "medium", "low"] as const;
const SEV_VAR: Record<string, string> = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)" };

export default function Queue({ user }: { user: Me }) {
  const [tab, setTab] = useState(() => memo.get("queue.tab", "active"));
  const [q, setQ] = useState(() => memo.get("queue.q", ""));
  const [sev, setSev] = useState<string | null>(() => memo.get("queue.sev", null));
  const [sel, setSel] = useState(0);
  const [running, setRunning] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  const ov = useLoad(api.overview);
  const list = useLoad(() => api.cases(tab === "all" ? {} : { status: tab }), [tab]);

  useEffect(() => { memo.set("queue.tab", tab); memo.set("queue.q", q); memo.set("queue.sev", sev); }, [tab, q, sev]);

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return (list.data ?? []).filter((c) => (!sev || c.severity === sev) &&
      (!ql || [c.id, c.title, ...c.rules, ...c.users, ...c.hosts, ...c.ips, ...c.mitre].join(" ").toLowerCase().includes(ql)));
  }, [list.data, q, sev]);

  useEffect(() => { memo.set("queue.order", rows.map((r) => r.id)); setSel((s) => Math.min(s, Math.max(0, rows.length - 1))); }, [rows]);

  useKeys({
    j: () => setSel((s) => Math.min(s + 1, rows.length - 1)),
    k: () => setSel((s) => Math.max(s - 1, 0)),
    Enter: () => rows[sel] && go(`case/${rows[sel].id}`),
    o: () => rows[sel] && go(`case/${rows[sel].id}`),
    "/": () => search.current?.focus(),
  }, [rows, sel]);

  const dist = useMemo(() => {
    const n: Record<string, number> = {};
    for (const c of list.data ?? []) if (c.severity) n[c.severity] = (n[c.severity] ?? 0) + 1;
    return n;
  }, [list.data]);

  async function runNow() {
    setRunning(true);
    try {
      const r = await api.run();
      toast(`${r.cases} case${r.cases === 1 ? "" : "s"} in ${r.seconds}s`);
      list.reload(); ov.reload();
    } catch (e) { toast((e as Error).message, true); } finally { setRunning(false); }
  }

  const o = ov.data;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Cases</h1>
        {user.role !== "viewer" && <Button className="btn-primary" busy={running} onClick={runNow}>Run Pipeline</Button>}
      </div>

      <section className="kpis" aria-label="Summary">
        <Kpi label="Open" value={o?.open} />
        <Kpi label="Needs Approval" value={o?.awaiting_approval} attention={!!o?.awaiting_approval} />
        <Kpi label="Incidents" value={o?.incidents_open} />
        <Kpi label="Actions Run" value={o?.actions?.executed} />
        <Kpi label="Model Spend 24h" value={o ? `$${o.model_cost_24h.toFixed(2)}` : undefined} />
      </section>

      <div className="toolbar">
        <div className="tabs" role="tablist" aria-label="Status">
          {TABS.map(([k, l]) => <button key={k} className="tab" role="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{l}</button>)}
        </div>
        <div className="tabs" role="group" aria-label="Severity">
          {SEVS.map((s) => (
            <button key={s} className="tab" aria-pressed={sev === s} aria-selected={sev === s} onClick={() => setSev(sev === s ? null : s)}>
              <span style={{ width: 8, height: 8, borderRadius: 4, background: SEV_VAR[s] }} aria-hidden />
              {s[0].toUpperCase() + s.slice(1)} <span className="num faint">{dist[s] ?? 0}</span>
            </button>
          ))}
        </div>
        <input ref={search} className="input grow" style={{ maxWidth: 320, marginLeft: "auto" }} type="search" placeholder="Search"
          value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search cases" />
      </div>

      <div className="card card-flush">
        {list.error ? <div style={{ padding: 16 }}><ErrorState error={list.error} retry={list.reload} /></div>
          : list.loading && !list.data ? <div style={{ padding: 16 }}><Loading rows={8} /></div>
          : rows.length === 0 ? (
            <Empty title={list.data?.length ? "No Matches" : "Yard's Quiet"}>
              {list.data?.length ? <button className="btn btn-sm" onClick={() => { setQ(""); setSev(null); }}>Clear Filters</button> : null}
            </Empty>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Severity</th><th className="right hide-sm">Risk</th><th>Case</th><th className="hide-sm">Entities</th><th className="hide-sm">Status</th><th className="right hide-sm">Last Seen</th></tr></thead>
                <tbody>{rows.map((c, i) => <CaseRow key={c.id} c={c} selected={i === sel} onEntity={setQ} />)}</tbody>
              </table>
            </div>
          )}
      </div>
      {rows.length > 0 && (
        <div className="row small faint" style={{ marginTop: 12, gap: 16 }}>
          <span><span className="kbd">j</span> <span className="kbd">k</span> Move</span>
          <span><span className="kbd">Enter</span> Open</span>
          <span><span className="kbd">/</span> Search</span>
        </div>
      )}
    </div>
  );
}

function Kpi({ label, value, attention }: { label: string; value: React.ReactNode; attention?: boolean }) {
  return (
    <div className={`kpi ${attention ? "attention" : ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value ?? <span className="skeleton" style={{ display: "inline-block", width: 48, height: 28 }} />}</div>
    </div>
  );
}

function CaseRow({ c, selected, onEntity }: { c: CaseSummary; selected: boolean; onEntity: (q: string) => void }) {
  const open = () => go(`case/${c.id}`);
  const ents = [...new Set([...c.users.slice(0, 1), ...c.hosts.slice(0, 1), ...c.ips.slice(0, 1)])].slice(0, 2);
  const rules = [...new Set(c.rules)];
  const ref = useRef<HTMLTableRowElement>(null);
  useEffect(() => { if (selected) ref.current?.scrollIntoView({ block: "nearest" }); }, [selected]);
  return (
    <tr ref={ref} className={`clickable ${selected ? "selected" : ""} ${c.status === "closed" ? "dim" : ""}`} onClick={open} tabIndex={0}
      onKeyDown={(e) => { if (e.key === "Enter") open(); }}>
      <td><SeverityPill severity={c.severity} /></td>
      <td className="right hide-sm"><Risk value={c.risk} /></td>
      <td style={{ width: "50%", maxWidth: 0 }}>
        <div className="ellipsis" style={{ fontWeight: 500 }} title={title(c.title)}>{title(c.title)}</div>
        <div className="small faint ellipsis">
          <span className="mono">{c.id}</span>
          {c.is_incident ? ` · ${c.rules.length} Alerts` : ` · ${rules.map(pretty).join(", ")}`}
        </div>
      </td>
      <td className="hide-sm"><div className="row" style={{ flexWrap: "nowrap" }}>{ents.map((e) => (
        <button key={e} className="tag link" title={`Filter by ${e}`} onClick={(ev) => { ev.stopPropagation(); onEntity(e); }}>{e}</button>
      ))}</div></td>
      <td className="hide-sm">
        <div className="row">
          <CaseStatus status={c.status} verdict={c.verdict} />
          {c.pending > 0 && <span className="badge" title={`${c.pending} pending`}>{c.pending}</span>}
          {c.suppressed && <span className="pill">Muted</span>}
        </div>
      </td>
      <td className="right small faint nowrap hide-sm">{ago(c.last_seen)}</td>
    </tr>
  );
}
