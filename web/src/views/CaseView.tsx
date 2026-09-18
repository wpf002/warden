import { useEffect, useState } from "react";
import { api, type Alert, type CaseFull, type Me } from "../api";
import { go, href } from "../router";
import { ActionStatus, Button, CaseStatus, Empty, ErrorState, Loading, SeverityPill, fmtTime, memo, pretty, title, titleCase, toast, useKeys, useLoad } from "../ui";

const FP_REASONS: [string, string][] = [
  ["known_scanner", "Authorized Scanner"], ["change_window", "Approved Change"], ["service_account", "Service Account"],
  ["travel", "Confirmed Travel"], ["test_activity", "Test Activity"], ["misconfiguration", "Misconfiguration"],
  ["duplicate", "Duplicate"], ["other", "Other"],
];

export default function CaseView({ id, user }: { id: string; user: Me }) {
  const c = useLoad(() => api.case(id), [id]);
  const order: string[] = memo.get("queue.order", []);
  const pos = order.indexOf(id);
  const prev = pos > 0 ? order[pos - 1] : null;
  const next = pos >= 0 && pos < order.length - 1 ? order[pos + 1] : null;
  const [tab, setTab] = useState("response");
  useEffect(() => setTab("response"), [id]);

  useKeys({
    j: () => next && go(`case/${next}`),
    k: () => prev && go(`case/${prev}`),
    Escape: () => go("queue"),
  }, [prev, next]);

  const head = (
    <div className="row" style={{ justifyContent: "space-between", marginBottom: 16 }}>
      <a href={href("queue")} className="small">&larr; Cases</a>
      <div className="row">
        {pos >= 0 && <span className="small faint num">{pos + 1} / {order.length}</span>}
        <button className="btn btn-sm" disabled={!prev} onClick={() => prev && go(`case/${prev}`)} aria-label="Previous case">
          <span className="kbd">k</span> Prev</button>
        <button className="btn btn-sm" disabled={!next} onClick={() => next && go(`case/${next}`)} aria-label="Next case">
          Next <span className="kbd">j</span></button>
      </div>
    </div>
  );
  if (c.error) return <div className="page">{head}<ErrorState error={c.error} retry={c.reload} /></div>;
  if (!c.data) return <div className="page">{head}<Loading rows={10} /></div>;

  const k = c.data;
  const set = (n: CaseFull) => c.setData(n);
  const canAct = user.role !== "viewer";
  const pending = k.actions.map((a, i) => [a, i] as const).filter(([a]) => a.status === "pending_approval");
  const anomalies = [k.alert, ...k.alert.members].filter((m) => m.detail?.source === "anomaly");
  const tabs: [string, string, number | null][] = [
    ["response", "Response", k.actions.length],
    ["timeline", "Timeline", k.alert.evidence.length],
    ...(k.alert.members.length ? [["chain", "Attack Chain", k.alert.members.length] as [string, string, number]] : []),
    ...(anomalies.length ? [["baseline", "Baseline", null] as [string, string, null]] : []),
    ["context", "Context", k.retrieved_docs.length],
    ["provenance", "Provenance", null],
  ];
  const afterVerdict = (n: CaseFull) => { set(n); if (next) setTimeout(() => go(`case/${next}`), 600); };

  return (
    <div className="page">
      {head}
      <header className="page-head" style={{ alignItems: "flex-start" }}>
        <div className="grow">
          <div className="row-wrap" style={{ marginBottom: 8 }}>
            <SeverityPill severity={k.analysis?.severity} />
            <CaseStatus status={k.status} verdict={k.analyst_verdict} />
            {k.alert.members.length > 0 && <span className="tag tag-accent">Incident · {k.alert.members.length} Alerts</span>}
            {k.suppressed_by != null && <span className="pill">Muted</span>}
            <span className="small faint mono">{k.alert.id}</span>
          </div>
          <h1 className="h1-plain" style={{ maxWidth: "80ch" }}>{title(k.alert.title)}</h1>
        </div>
        {canAct && !k.analyst_verdict && <VerdictControls k={k} onDone={afterVerdict} />}
      </header>

      <div className="grid-2-1" style={{ marginBottom: 24 }}>
        <section className="card" aria-label="Analysis">
          <h2>What Happened</h2>
          {k.analysis ? (
            <>
              <p className="summary" style={{ margin: "0 0 12px" }}>{k.analysis.explanation}</p>
              <div className="row-wrap">{k.alert.mitre.slice(0, 8).map((t) => <span key={t} className="tag">{t}</span>)}</div>
              {k.verification.length > 0 && (
                <div className="callout callout-warn" style={{ marginTop: 16 }}>
                  <strong>Held For Review</strong>
                  <ul style={{ margin: "8px 0 0", paddingLeft: 24 }}>{k.verification.map((v) => <li key={v}>{v}</li>)}</ul>
                </div>
              )}
            </>
          ) : <p className="muted" style={{ margin: 0 }}>{k.suppressed_by != null ? "Muted by exclusion; not analyzed." : "Not analyzed."}</p>}
        </section>
        <Facts k={k} />
      </div>

      {pending.length > 0 && canAct && k.status !== "closed" && (
        <section className="card" style={{ borderColor: "var(--searchlight)", marginBottom: 24 }} aria-label="Needs approval">
          <h2 style={{ color: "var(--searchlight)" }}>Needs Approval</h2>
          <div className="stack-12">{pending.map(([a, i]) => <PendingAction key={i} k={k} idx={i} set={set} a={a} />)}</div>
        </section>
      )}

      <div className="tabbar" role="tablist">
        {tabs.map(([key, label, n]) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}>
            {label}{n != null && <span className="count">{n}</span>}
          </button>
        ))}
      </div>
      {tab === "response" && <Actions k={k} set={set} canAct={canAct} />}
      {tab === "timeline" && <Timeline alert={k.alert} />}
      {tab === "chain" && <Chain members={k.alert.members} />}
      {tab === "baseline" && <Baseline anomalies={anomalies} />}
      {tab === "context" && <Context k={k} />}
      {tab === "provenance" && <Provenance k={k} />}
    </div>
  );
}

function Facts({ k }: { k: CaseFull }) {
  const a = k.alert;
  const intel: Record<string, any[]> = Object.assign({}, ...[a, ...a.members].map((m) => m.detail?.intel ?? {}));
  const ips = [...new Set([a.source_ip, ...a.related_ips].filter(Boolean))];
  const Chips = ({ items }: { items: string[] }) => (
    <div className="row-wrap">{items.slice(0, 8).map((x) => (
      <a key={x} className="tag link" href={href("queue")} onClick={() => memo.set("queue.q", x)} title={`All cases with ${x}`}>
        {x}{intel[x] && <span style={{ color: "var(--critical)", marginLeft: 4 }}>●</span>}</a>
    ))}{items.length > 8 && <span className="small faint">+{items.length - 8}</span>}</div>
  );
  return (
    <section className="card" aria-label="Facts">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h3>Risk</h3>
          <div className="risk-big">{k.analysis?.risk_score ?? "-"}</div>
        </div>
        <dl className="kv small" style={{ marginTop: 4 }}>
          <dt>FP Likelihood</dt><dd>{k.analysis ? titleCase(k.analysis.false_positive_likelihood) : "-"}</dd>
          <dt>Asset Tier</dt><dd>{titleCase(a.asset_tier)}</dd>
          <dt>Window</dt><dd className="num">{fmtTime(a.first_seen)}–{fmtTime(a.last_seen)}</dd>
        </dl>
      </div>
      <hr className="divider" />
      <div className="stack-12">
        {a.users.length > 0 && <div><h3>Users</h3><Chips items={a.users} /></div>}
        {a.hosts.length > 0 && <div><h3>Hosts</h3><Chips items={a.hosts} /></div>}
        {ips.length > 0 && <div><h3>IPs</h3><Chips items={ips} /></div>}
      </div>
    </section>
  );
}

function VerdictControls({ k, onDone }: { k: CaseFull; onDone: (c: CaseFull) => void }) {
  const [fp, setFp] = useState(false);
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");
  const [mute, setMute] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  async function submit(verdict: string) {
    setBusy(verdict);
    try {
      onDone(await api.verdict(k.alert.id, { verdict, note, reason: verdict === "false_positive" ? reason : "", suppress: mute }));
      toast(verdict === "true_positive" ? "Marked True Positive" : "Marked False Positive");
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(null); }
  }
  if (!fp) {
    return (
      <div className="header-actions">
        <Button className="btn-primary" busy={busy === "true_positive"} onClick={() => submit("true_positive")}>True Positive</Button>
        <Button onClick={() => setFp(true)}>False Positive</Button>
      </div>
    );
  }
  return (
    <div className="card stack-12" style={{ width: 320, boxShadow: "var(--shadow-float)" }}>
      <div className="field">
        <label htmlFor="fp-reason">Reason</label>
        <select id="fp-reason" className="select" value={reason} onChange={(e) => setReason(e.target.value)} autoFocus>
          <option value="">Choose</option>
          {FP_REASONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </div>
      <input className="input" placeholder="Note" value={note} onChange={(e) => setNote(e.target.value)} />
      <label className="row small"><input type="checkbox" checked={mute} onChange={(e) => setMute(e.target.checked)} /> Mute 30 Days</label>
      <div className="row">
        <Button className="btn-primary" busy={busy === "false_positive"} disabled={!reason} onClick={() => submit("false_positive")}>Confirm</Button>
        <Button className="btn-ghost" onClick={() => setFp(false)}>Cancel</Button>
      </div>
    </div>
  );
}

function PendingAction({ k, idx, set, a }: { k: CaseFull; idx: number; set: (c: CaseFull) => void; a: CaseFull["actions"][number] }) {
  const [busy, setBusy] = useState<string | null>(null);
  async function op(o: "approve" | "deny") {
    setBusy(o);
    try { set(await api.action(k.alert.id, idx, o)); toast(`${o === "approve" ? "Approved" : "Denied"}: ${titleCase(a.action)} ${a.target}`); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(null); }
  }
  return (
    <div className="row-12">
      <div className="grow row-wrap">
        <strong style={{ fontWeight: 500 }}>{titleCase(a.action)}</strong><span className="tag">{a.target}</span>
        <span className="small faint">{a.detail}</span>
      </div>
      <Button className="btn-primary btn-sm" busy={busy === "approve"} disabled={!!busy} onClick={() => op("approve")}>Approve</Button>
      <Button className="btn-sm" busy={busy === "deny"} disabled={!!busy} onClick={() => op("deny")}>Deny</Button>
    </div>
  );
}

function Actions({ k, set, canAct }: { k: CaseFull; set: (c: CaseFull) => void; canAct: boolean }) {
  const [busy, setBusy] = useState<number | null>(null);
  if (!k.actions.length) return <div className="card"><Empty title="No Actions" /></div>;
  async function rollback(i: number) {
    setBusy(i);
    try { set(await api.action(k.alert.id, i, "rollback")); toast("Rolled Back"); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(null); }
  }
  return (
    <section className="card card-flush">
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Status</th><th>Action</th><th>Target</th><th>Connector</th><th>Result</th><th /></tr></thead>
          <tbody>{k.actions.map((a, i) => (
            <tr key={i}>
              <td><ActionStatus status={a.status} /></td>
              <td className="nowrap">{titleCase(a.action)}</td>
              <td><span className="tag">{a.target || "-"}</span></td>
              <td className="small mono">{a.connector || "-"}{a.dry_run && <span className="faint"> (dry run)</span>}</td>
              <td className="small muted" style={{ maxWidth: 420 }}><div className="ellipsis" title={a.detail}>{a.detail}</div></td>
              <td className="right">{canAct && a.status === "executed" && Object.keys(a.receipt || {}).length > 0 &&
                <Button className="btn-sm btn-ghost" busy={busy === i} onClick={() => rollback(i)}>Roll Back</Button>}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <details style={{ padding: "12px 16px", borderTop: "1px solid var(--border)" }}>
        <summary>Guardrail Log</summary>
        <pre className="code" style={{ marginTop: 8 }}>{k.guardrail_log.join("\n")}</pre>
      </details>
    </section>
  );
}

function Chain({ members }: { members: Alert[] }) {
  return (
    <section className="card card-flush">
      <table className="table">
        <thead><tr><th>Step</th><th>Time</th><th>Detection</th><th>ATT&amp;CK</th><th>Finding</th></tr></thead>
        <tbody>{members.map((m, i) => (
          <tr key={m.id}><td className="num">{i + 1}</td><td className="mono small">{fmtTime(m.first_seen)}</td>
            <td style={{ fontWeight: 500 }}>{pretty(m.rule)}</td>
            <td><div className="row-wrap">{m.mitre.slice(0, 2).map((t) => <span key={t} className="tag">{t}</span>)}</div></td>
            <td className="small muted" style={{ maxWidth: 520 }}><div className="ellipsis" title={m.title}>{m.title}</div></td></tr>
        ))}</tbody>
      </table>
    </section>
  );
}

function Baseline({ anomalies }: { anomalies: Alert[] }) {
  return (
    <div className="stack-16">{anomalies.map((m) => (
      <section key={m.id} className="card card-flush">
        <div className="card-head"><h2>{titleCase(m.detail.entity_type)} {m.detail.entity}</h2>
          <span className="small faint">Score {m.detail.score} · {m.detail.baseline_days}-Day Baseline</span></div>
        <table className="table"><tbody>{(m.detail.contributions ?? []).map((c: any, i: number) => (
          <tr key={i}><td className="num right" style={{ width: 64 }}>+{c.score}</td><td>{c.why}</td>
            <td className="small faint">{c.kind === "volume" ? "Volume" : c.kind === "iforest" ? "Second Opinion" : "First Seen"}</td></tr>
        ))}</tbody></table>
      </section>
    ))}</div>
  );
}

function Timeline({ alert }: { alert: Alert }) {
  const ev = alert.evidence;
  if (!ev.length) return <div className="card"><Empty title="No Events" /></div>;
  const first = new Set<number>();
  let prev = "";
  ev.forEach((e, i) => { if (e.rule && e.rule !== prev) { first.add(i); prev = e.rule; } });
  return (
    <section className="card">
      <div className="timeline">
        {ev.map((e, i) => (
          <div key={i} className={`tl-item ${first.has(i) ? "key" : ""}`}>
            <div className="tl-time">{e.ts ? fmtTime(e.ts) : ""}</div>
            <div className="tl-rail"><span className="tl-dot" /></div>
            <div className="small" style={{ minWidth: 0 }}>
              {first.has(i) && <div style={{ fontWeight: 500 }}>{pretty(e.rule)}</div>}
              <span className="mono" style={{ fontSize: 12 }}>{String(e.type ?? "")}</span>
              {e.user && <span className="faint"> · {e.user}</span>}{e.host && <span className="faint"> · {e.host}</span>}
              {e.cmd && <div className="mono faint ellipsis" style={{ fontSize: 12 }} title={e.cmd}>{e.cmd}</div>}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Context({ k }: { k: CaseFull }) {
  if (!k.retrieved_docs.length) return <div className="card"><Empty title="No Context" /></div>;
  return (
    <div className="stack-16">{k.retrieved_docs.map((d) => (
      <section key={d.id} className="card">
        <div className="row-wrap small" style={{ marginBottom: 8 }}><a href={href(`knowledge/${d.doc}`)} className="mono">{d.id}</a>
          <span className="tag">{titleCase(d.kind)}</span></div>
        <pre className="code" style={{ whiteSpace: "pre-wrap", maxHeight: 240 }}>{d.text.slice(0, 1200)}</pre>
      </section>
    ))}</div>
  );
}

function Provenance({ k }: { k: CaseFull }) {
  const call = k.llm_calls[0];
  return (
    <section className="card">
      <dl className="kv">
        <dt>Model</dt><dd>{k.model || "-"}</dd>
        <dt>Prompt</dt><dd className="mono">{k.prompt_version || "-"}</dd>
        <dt>KB Snapshot</dt><dd className="mono">{k.kb_snapshot || "-"}</dd>
        <dt>Tokens</dt><dd className="num">{call ? `${call.input_tokens ?? "-"} In · ${call.output_tokens ?? "-"} Out` : "-"}</dd>
        <dt>Cost</dt><dd className="num">{call?.cost_usd != null ? `$${call.cost_usd.toFixed(4)}` : "-"}</dd>
        <dt>Stages</dt><dd className="num">{k.spans.length ? k.spans.map((s) => `${titleCase(s.span)} ${Math.round(s.ms)}ms`).join(" · ") : "-"}</dd>
        <dt>Verdict</dt><dd>{k.analyst_verdict ? `${titleCase(k.analyst_verdict)}${k.analyst_note ? ` · ${k.analyst_note}` : ""}` : "-"}</dd>
      </dl>
    </section>
  );
}
