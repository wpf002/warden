import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, type Severity } from "./api";

// ---------------------------------------------------------------- data loading
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const reload = useCallback(() => {
    const n = ++seq.current;
    setLoading(true);
    fn().then((d) => { if (n === seq.current) { setData(d); setError(null); } })
      .catch((e) => { if (n === seq.current) setError(e); })
      .finally(() => { if (n === seq.current) setLoading(false); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { data, error, loading, reload, setData };
}

// ---------------------------------------------------------------- states
export function Loading({ rows = 5 }: { rows?: number }) {
  return (
    <div className="stack-8" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" style={{ width: `${90 - i * 9}%` }} />)}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  const status = error instanceof ApiError ? error.status : 0;
  const msg = status === 401 ? "Signed out. Reload to sign in."
    : status === 403 ? "Your role can't open this."
    : status === 404 ? "Not found."
    : status >= 500 ? "Server error. Try again." : error.message;
  return (
    <div className="callout callout-danger row-12" role="alert">
      <span className="grow">{msg}</span>
      {retry && status !== 403 && status !== 404 && <button className="btn btn-sm" onClick={retry}>Retry</button>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><div className="title">{title}</div>{children && <div className="small">{children}</div>}</div>;
}

// ---------------------------------------------------------------- toasts
let pushToast: (t: { msg: string; err?: boolean }) => void = () => {};
export function toast(msg: string, err = false) { pushToast({ msg, err }); }
export function Toasts() {
  const [t, setT] = useState<{ msg: string; err?: boolean } | null>(null);
  useEffect(() => {
    pushToast = (x) => setT(x);
    return () => { pushToast = () => {}; };
  }, []);
  useEffect(() => { if (!t) return; const h = setTimeout(() => setT(null), 4000); return () => clearTimeout(h); }, [t]);
  return t ? <div className={`toast ${t.err ? "err" : ""}`} role="status">{t.msg}</div> : null;
}

// ---------------------------------------------------------------- atoms
const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

export function SeverityPill({ severity }: { severity: Severity | null | undefined }) {
  if (!severity) return <span className="pill">Unscored</span>;
  // shape as well as color: critical is filled, others are rings, so severity never rests on hue alone
  return <span className={`pill sev-${severity}`}><span className="dot" aria-hidden />{SEV_LABEL[severity]}</span>;
}

const RISK_COLOR = (r: number) => (r >= 85 ? "var(--critical)" : r >= 70 ? "var(--serious)" : r >= 45 ? "var(--warning)" : "var(--text-faint)");

export function Risk({ value }: { value: number | null | undefined }) {
  if (value == null) return <span className="faint">-</span>;
  return (
    <span className="risk" title={`Risk ${value} of 100`}>
      <span className="num" style={{ minWidth: 28, textAlign: "right" }}>{value}</span>
      <span className="risk-bar" aria-hidden><span style={{ width: `${value}%`, background: RISK_COLOR(value) }} /></span>
    </span>
  );
}

const STATUS_LABEL: Record<string, string> = {
  executed: "Executed", pending_approval: "Needs Approval", denied: "Denied", failed: "Failed", rolled_back: "Rolled Back",
};
export function ActionStatus({ status }: { status: string }) {
  return <span className={`pill st-${status}`}>{STATUS_LABEL[status] ?? status}</span>;
}

export function CaseStatus({ status, verdict }: { status: string; verdict?: string | null }) {
  if (verdict) return <span className="pill">{verdict === "true_positive" ? "True Positive" : "False Positive"}</span>;
  if (status === "awaiting_approval") return <span className="pill st-pending_approval">Needs Approval</span>;
  if (status === "closed") return <span className="pill">Closed</span>;
  return <span className="pill">Open</span>;
}

export function Button({ busy, children, className = "", ...rest }:
  React.ButtonHTMLAttributes<HTMLButtonElement> & { busy?: boolean }) {
  return (
    <button className={`btn ${className}`} disabled={busy || rest.disabled} aria-busy={busy} {...rest}>
      {busy && <span className="spinner" aria-hidden />}{children}
    </button>
  );
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return "-";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 60) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toISOString().slice(0, 10);
}

export function fmtTime(iso: string, withDate = false) {
  const d = new Date(iso);
  const t = d.toISOString().slice(11, 19);
  return withDate ? `${d.toISOString().slice(0, 10)} ${t}` : t;
}

const ACRONYMS: Record<string, string> = {
  mfa: "MFA", ip: "IP", iam: "IAM", dns: "DNS", lsass: "LSASS", aws: "AWS", no: "No", ioc: "IOC", tp: "TP", fp: "FP",
  vpn: "VPN", edr: "EDR", kb: "KB", ad: "AD", sso: "SSO", api: "API", ttl: "TTL", id: "ID",
  powershell: "PowerShell", lolbin: "LOLBin", fanout: "Fan-Out", nacl: "NACL", smtp: "SMTP", evtx: "EVTX",
};
const SMALL = new Set(["a", "an", "and", "as", "at", "by", "for", "in", "of", "on", "or", "the", "to", "via", "with"]);

/** Title Case with security acronyms kept upright: "mfa_method_change" -> "MFA Method Change". */
export function titleCase(s: string): string {
  return s.replace(/_/g, " ").split(/(\s+)/).map((w, i) => {
    const lw = w.toLowerCase();
    if (ACRONYMS[lw]) return ACRONYMS[lw];
    if (i > 0 && SMALL.has(lw)) return lw;
    return w ? w[0].toUpperCase() + w.slice(1) : w;
  }).join("");
}

export const pretty = (rule: string) => rule.startsWith("anomaly.") ? `${titleCase(rule.slice(8))} Anomaly` : titleCase(rule);

/** Incident titles chain rule names with "->"; show a real arrow. */
export const title = (t: string) => {
  const i = t.indexOf(": ");
  // incident titles are "<focus>: rule -> rule -> rule"; title-case the chain, keep the entity as written
  if (i > 0 && t.includes(" -> ")) return `${t.slice(0, i)}: ${t.slice(i + 2).split(" -> ").map(titleCase).join(" → ")}`;
  return t;
};

// ---------------------------------------------------------------- tiny charts
/** Weekly fire counts. Single series, so no legend; the column header names it. */
export function Sparkline({ values, label }: { values: number[]; label: string }) {
  const w = 96, h = 24, max = Math.max(1, ...values);
  const bw = w / values.length;
  return (
    <svg width={w} height={h} role="img" aria-label={`${label}: ${values.join(", ")} (oldest first)`}>
      {values.map((v, i) => (
        <rect key={i} x={i * bw + 1} y={h - Math.max(1, (v / max) * h)} width={bw - 2} height={Math.max(1, (v / max) * h)}
          rx={2} fill={v ? "var(--series-1)" : "var(--border)"}>
          <title>{`${values.length - 1 - i} weeks ago: ${v}`}</title>
        </rect>
      ))}
    </svg>
  );
}

export function RateBar({ value }: { value: number | null }) {
  if (value == null) return <span className="faint small">-</span>;
  const pct = Math.round(value * 100);
  const color = value >= 0.5 ? "var(--critical)" : value >= 0.25 ? "var(--warning)" : "var(--good)";
  return (
    <span className="row">
      <span className="bar-track" aria-hidden><span style={{ width: `${pct}%`, background: color }} /></span>
      <span className="num small">{pct}%</span>
    </span>
  );
}

// ---------------------------------------------------------------- navigation memory
/** The queue remembers its filters and the order it showed, so a case page can offer
 *  previous/next and "back" lands where the analyst left off. */
export const memo = {
  get<T>(k: string, d: T): T { try { const v = sessionStorage.getItem(`warden:${k}`); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k: string, v: unknown) { try { sessionStorage.setItem(`warden:${k}`, JSON.stringify(v)); } catch { /* storage off */ } },
};

export function useKeys(map: Record<string, (e: KeyboardEvent) => void>, deps: unknown[] = []) {
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.metaKey || e.ctrlKey || e.altKey || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName)) return;
      const fn = map[e.key === "Return" ? "Enter" : e.key];
      if (fn) { e.preventDefault(); fn(e); }
    };
    addEventListener("keydown", on);
    return () => removeEventListener("keydown", on);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
