const EVENT_WORDS: Record<string, string> = {
  login_success: "Signed in", login_failure: "Failed sign-in", lockout: "Locked out", logout: "Signed out",
  mfa_challenge: "MFA prompt", mfa_denied: "MFA denied", mfa_timeout: "MFA timed out", mfa_success: "MFA approved",
  start: "Ran a program", service_installed: "Service installed", task_created: "Scheduled task created",
  log_cleared: "Event log cleared", script_block: "Script ran", create: "File written", delete: "File deleted",
  rename: "File renamed", modify: "File changed", read: "File read",
};

/** The raw evidence is one row per log line. An analyst wants the story: collapse runs of the
 *  same event on the same user and host into a single line with a count. */
function Timeline({ alert }: { alert: Alert }) {
  const [all, setAll] = useState(false);
  const ev = alert.evidence;
  if (!ev.length) return <div className="card"><Empty title="No Events" /></div>;

  const groups: any[] = [];
  let prevRule = "";
  for (const e of ev) {
    const key = `${e.type}|${e.user ?? ""}|${e.host ?? ""}|${e.rule ?? ""}`;
    const last = groups[groups.length - 1];
    if (last && last.key === key && !e.cmd) { last.count += 1; last.end = e.ts; continue; }
    const isNew = !!e.rule && e.rule !== prevRule;
    if (e.rule) prevRule = e.rule;
    groups.push({ key, ts: e.ts, end: e.ts, count: 1, type: e.type, user: e.user, host: e.host,
                  cmd: e.cmd, rule: e.rule, stage: isNew });
  }
  const shown = all ? groups : groups.slice(0, 25);
  return (
    <section className="card card-flush">
      <div className="timeline-scroll">
        <div className="timeline">
          {shown.map((g, i) => (
            <div key={i} className={`tl-item ${g.stage ? "key" : ""}`}>
              <div className="tl-time">{g.ts ? fmtTime(g.ts) : ""}</div>
              <div className="tl-rail"><span className="tl-dot" /></div>
              <div style={{ minWidth: 0 }}>
                {g.stage && <div className="tl-stage">{pretty(g.rule)}</div>}
                <span>{EVENT_WORDS[String(g.type ?? "")] ?? titleCase(String(g.type ?? "event"))}</span>
                {g.count > 1 && <span className="tl-count">×{g.count}</span>}
                {g.user && <span className="faint"> · {g.user}</span>}
                {g.host && <span className="faint"> · {g.host}</span>}
                {g.cmd && <div className="mono faint ellipsis" style={{ fontSize: 12 }} title={g.cmd}>{g.cmd}</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
      {groups.length > 25 && (
        <div className="card-head" style={{ borderTop: "1px solid var(--border)", borderBottom: "none" }}>
          <span className="small faint">{shown.length} of {groups.length} steps · {ev.length} raw events</span>
          <button className="btn btn-ghost btn-sm" onClick={() => setAll(!all)}>{all ? "Show Less" : "Show All"}</button>
        </div>
      )}
    </section>
  );
}

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
    ["provenance", "Analysis Record", null],
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
          <h1 className="h1-plain" style={{ maxWidth: "70ch" }}>{k.analysis?.headline || title(k.alert.title)}</h1>
          {k.analysis?.headline && k.alert.members.length > 0 && (
            <div className="chain-strip small">{[...new Set(k.alert.members.map((m) => m.rule))].map((r) => (
              <span key={r}>{pretty(r)}</span>
            ))}</div>
          )}
        </div>
        {/* keyed by case: moving to the next case closes a half-filled false-positive form */}
        {canAct && !k.analyst_verdict && <VerdictControls key={k.alert.id} k={k} onDone={afterVerdict} />}
      </header>

      <div className="grid-2-1" style={{ marginBottom: 24 }}>
        <section className="card" aria-label="Analysis">
          <h2>What Happened</h2>
          {k.analysis ? (
            <>
              <Explanation text={k.analysis.explanation} />
              {k.analysis.next_step && (
                <div className="next-step"><span className="label">Next Step</span><p>{k.analysis.next_step}</p></div>
              )}
              <details className="mitre"><summary className="small faint">ATT&amp;CK Techniques ({k.alert.mitre.length})</summary>
                <div className="row-wrap" style={{ marginTop: 8 }}>{k.alert.mitre.map((t) => <span key={t} className="tag">{t}</span>)}</div>
              </details>
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
          <div className="pending-list">{pending.map(([a, i]) => <PendingAction key={i} k={k} idx={i} set={set} a={a} />)}</div>
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

/** A chain reads as steps, not as one run-on sentence: split the model's "; then" chain into a list. */
function humanize(t: string): string {
  return t
    .replace(/^\d+-stage chain on \S+:\s*/i, "")
    .replace(/Unusual day for (?:user|host) (\S+): logins (\d+), baseline ([\d.]+)[^;]*; failures (\d+), baseline ([\d.]+)[^.]*/i,
      (_m, who, li, lb, fi, fb) => `${who} signed in ${li} times (normally about ${Math.round(+lb)}) and failed ${fi} times (normally about ${Math.round(+fb)})`)
    .replace(/\(z=[\d.]+\)/g, "")
    .replace(/\bSUCCESS for (\S+)/g, "and $1's password worked")
    .replace(/\b0 min after\b/g, "seconds after")
    .replace(/(\d+) min after\b/g, "$1 minutes after")
    .replace(/every (\d+)s \(jitter [^)]*\)/g, (_m, sec) => `every ${Math.round(+sec / 60)} minutes, like clockwork`)
    .replace(/\bPowerShell encoded \+ hidden\b/g, "hidden, encoded PowerShell ran")
    .replace(/\bspawned\b/g, "launched")
    .replace(/\breached (\d+) hosts over 445\b/g, "connected to $1 file shares")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function Explanation({ text }: { text: string }) {
  const parts = humanize(text).split(/;\s*then\s+/i).map((p) => humanize(p)).filter(Boolean);
  if (parts.length < 3) return <p className="summary" style={{ margin: "0 0 16px" }}>{text}</p>;
  const [lead, ...rest] = parts;
  return (
    <div style={{ marginBottom: 16 }}>
      <p className="summary" style={{ margin: "0 0 12px" }}>{lead.replace(/:$/, "")}</p>
      <ol className="steps">{rest.map((p, i) => <li key={i}>{p.replace(/\.$/, "")}</li>)}</ol>
    </div>
  );
}

function Facts({ k }: { k: CaseFull }) {
  const a = k.alert;
  const [open, setOpen] = useState(false);
  const intel: Record<string, any[]> = Object.assign({}, ...[a, ...a.members].map((m) => m.detail?.intel ?? {}));
  const ips = [...new Set([a.source_ip, ...a.related_ips].filter(Boolean))];
  const cap = open ? 100 : 6;
  const Chips = ({ label, items }: { label: string; items: string[] }) => items.length === 0 ? null : (
    <div className="fact-group">
      <div className="fact-label">{label} <span className="faint">{items.length}</span></div>
      <div className="row-wrap">{items.slice(0, cap).map((x) => (
        <a key={x} className="tag link" href={href("queue")} onClick={() => memo.set("queue.q", x)} title={`All cases with ${x}`}>
          {x}{intel[x] && <span style={{ color: "var(--critical)", marginLeft: 4 }}>●</span>}</a>
      ))}{items.length > cap && <button className="tag link" onClick={() => setOpen(true)}>+{items.length - cap} more</button>}</div>
    </div>
  );
  return (
    <section className="card facts" aria-label="Facts">
      <div className="risk-row">
        <div>
          <div className="fact-label">Risk</div>
          <div className="risk-big">{k.analysis?.risk_score ?? "-"}</div>
        </div>
        <dl className="kv small">
          <dt>False Positive</dt><dd>{k.analysis ? titleCase(k.analysis.false_positive_likelihood) : "-"}</dd>
          <dt>Asset</dt><dd>{titleCase(a.asset_tier)}</dd>
          <dt>Window</dt><dd className="num">{fmtTime(a.first_seen)}–{fmtTime(a.last_seen)}</dd>
        </dl>
      </div>
      <hr className="divider" />
      <Chips label="Users" items={a.users} />
      <Chips label="Hosts" items={a.hosts} />
      <Chips label="Addresses" items={ips} />
      {open && <button className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>Show Less</button>}
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
    <div className="card verdict-form" style={{ width: 340, boxShadow: "var(--shadow-float)" }}>
      <div className="field">
        <label htmlFor="fp-reason">Why is this a false positive?</label>
        <select id="fp-reason" className="select" value={reason} onChange={(e) => setReason(e.target.value)} autoFocus>
          <option value="">Choose a reason</option>
          {FP_REASONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </div>
      <div className="field">
        <label htmlFor="fp-note">Note <span className="faint">(optional)</span></label>
        <input id="fp-note" className="input" placeholder="What made it benign?" value={note}
          onChange={(e) => setNote(e.target.value)} />
      </div>
      <label className="check"><input type="checkbox" checked={mute} onChange={(e) => setMute(e.target.checked)} />
        <span>Mute this rule for this entity, 30 days</span></label>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <Button className="btn-ghost" onClick={() => setFp(false)}>Cancel</Button>
        <Button className="btn-primary" busy={busy === "false_positive"} disabled={!reason}
          onClick={() => submit("false_positive")}>Confirm</Button>
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
    <div className="pending-row">
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

const FEATURE_WORDS: Record<string, [string, string]> = {
  logins: ["signed in", "times"], failures: ["failed to sign in", "times"],
  distinct_hosts: ["touched", "different machines"], distinct_src_nets: ["connected from", "different networks"],
  processes: ["ran", "programs"], distinct_processes: ["ran", "different programs"],
  directory_changes: ["made", "directory changes"], mfa_denials: ["denied", "MFA prompts"],
  process_starts: ["started", "programs"], connections_out: ["made", "outbound connections"],
  distinct_destinations: ["talked to", "different destinations"], bytes_out_mb: ["sent", "MB out"],
  dns_queries: ["made", "DNS queries"], file_writes: ["wrote", "files"],
  internal_destinations: ["reached", "internal machines"],
};

/** Turn "logins 109, baseline 15.6 +/- 24.8 (z=3.8)" into something a person reads once. */
function whyPlain(c: any): string {
  if (c.kind === "iforest") return "A second, machine-learning check flags this day too";
  const m = /^([a-z_ ]+?)\s+([\d.]+), baseline ([\d.]+)/.exec(String(c.why ?? ""));
  if (c.kind === "volume" && m) {
    const key = m[1].trim().replace(/ /g, "_");
    const [verb, unit] = FEATURE_WORDS[key] ?? [m[1].trim(), ""];
    return `${verb} ${Math.round(+m[2])} ${unit}, normally about ${Math.round(+m[3])}`.replace(/\s+/g, " ");
  }
  return String(c.why ?? "").replace(/\(z=[\d.]+\)/g, "").replace(/^first /, "first time using ").trim();
}

function Baseline({ anomalies }: { anomalies: Alert[] }) {
  return (
    <div className="stack-16">{anomalies.map((m) => (
      <section key={m.id} className="card card-flush">
        <div className="card-head">
          <h2>{titleCase(m.detail.entity_type)} {m.detail.entity}</h2>
          <span className="small faint">Compared with {m.detail.baseline_days} days of their normal activity</span>
        </div>
        <ul className="why-list">{(m.detail.contributions ?? []).map((c: any, i: number) => (
          <li key={i}>
            <span className={`why-bar ${c.kind}`} style={{ width: `${Math.min(100, (c.score / 10) * 100)}%` }} />
            <span className="why-text">{titleCase(m.detail.entity)} {whyPlain(c)}</span>
          </li>
        ))}</ul>
      </section>
    ))}</div>
  );
}

function Context({ k }: { k: CaseFull }) {
  const [open, setOpen] = useState<string | null>(null);
  if (!k.retrieved_docs.length) return <div className="card"><Empty title="No Context" /></div>;
  return (
    <div className="stack-16">{k.retrieved_docs.map((d) => {
      const full = open === d.id;
      const text = d.text.replace(/\s*\n\s*/g, "\n").trim();
      const body = full ? text : text.slice(0, 420);
      return (
        <section key={d.id} className="card">
          <div className="row-wrap" style={{ marginBottom: 8, justifyContent: "space-between" }}>
            <a href={href(`knowledge/${d.doc}`)} style={{ fontWeight: 500 }}>{titleCase(d.doc.replace(/^(playbook|policy|attack)-/, ""))}</a>
            <span className="tag">{d.kind === "attack" ? "MITRE ATT&CK" : titleCase(d.kind)}</span>
          </div>
          <div className="kb-text">{body.split("\n").filter(Boolean).slice(0, full ? 200 : 6).map((line, i) => (
            <p key={i}>{line.replace(/^[-*]\s*/, "")}</p>
          ))}</div>
          {text.length > 420 && (
            <button className="btn btn-ghost btn-sm" onClick={() => setOpen(full ? null : d.id)}>
              {full ? "Show Less" : "Read More"}</button>
          )}
        </section>
      );
    })}</div>
  );
}

function Provenance({ k }: { k: CaseFull }) {
  const call = k.llm_calls[0];
  return (
    <section className="card stack-16">
      <p className="muted" style={{ margin: 0 }}>
        How this case was analyzed, so any conclusion can be traced back and re-run exactly as it was.
      </p>
      <dl className="kv">
        <dt>Analyzed By</dt><dd>{k.model || "-"}</dd>
        <dt>Instructions Version</dt><dd className="mono">{k.prompt_version || "-"}</dd>
        <dt>Knowledge Base Version</dt><dd className="mono">{k.kb_snapshot || "-"}</dd>
        <dt>Text Read And Written</dt><dd className="num">{call ? `${call.input_tokens ?? "-"} in · ${call.output_tokens ?? "-"} out` : "Offline analyzer, nothing sent"}</dd>
        <dt>Cost</dt><dd className="num">{call?.cost_usd != null ? `$${call.cost_usd.toFixed(4)}` : "$0"}</dd>
        <dt>Time Taken</dt><dd className="num">{k.spans.length ? k.spans.map((s) => `${titleCase(s.span)} ${Math.round(s.ms)}ms`).join(" · ") : "-"}</dd>
        <dt>Analyst Verdict</dt><dd>{k.analyst_verdict ? `${titleCase(k.analyst_verdict)}${k.analyst_note ? ` · ${k.analyst_note}` : ""}` : "Not reviewed yet"}</dd>
      </dl>
    </section>
  );
}
