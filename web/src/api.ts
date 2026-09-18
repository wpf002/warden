// Thin client for /api/v1. Every call carries the browser's auth (basic auth or the
// OIDC proxy's cookie); the server scopes everything to the caller's tenant.

export type Severity = "critical" | "high" | "medium" | "low";

export interface CaseSummary {
  id: string; title: string; ts: string; first_seen: string; last_seen: string;
  rules: string[]; is_incident: boolean; mitre: string[];
  severity: Severity | null; risk: number | null; fp_likelihood: string | null;
  status: "open" | "awaiting_approval" | "closed"; verdict: string | null; suppressed: boolean;
  users: string[]; hosts: string[]; ips: string[]; asset_tier: string;
  pending: number; executed: number; sources: string[];
}

export interface Alert {
  id: string; ts: string; rule: string; title: string; mitre: string[]; playbook: string;
  source_ip: string; related_ips: string[]; users: string[]; hosts: string[]; geo: string; asset_tier: string;
  first_seen: string; last_seen: string; window_sec: number; failed_attempts: number; success_after_failures: boolean;
  detail: Record<string, any>; evidence: Record<string, any>[]; members: Alert[];
}

export interface ActionResult {
  action: string; target: string; status: string; detail: string; connector: string; dry_run: boolean;
  receipt: Record<string, any>; ts: string;
}

export interface CaseFull {
  alert: Alert; retrieved_docs: { id: string; text: string; doc: string; kind: string; technique?: string }[];
  analysis: null | {
    explanation: string; mitre_attack: string; risk_score: number; severity: Severity;
    false_positive_likelihood: string; recommended_actions: { action: string; target: string; reason: string }[];
    citations: string[];
  };
  guardrail_log: string[]; actions: ActionResult[]; analyst_verdict: string | null; analyst_note: string;
  analyst_reason: string; suppressed_by: number | null; status: string; incident_id: string | null;
  prompt_version: string; kb_snapshot: string; model: string; verification: string[];
  spans: { span: string; ms: number }[];
  summary: CaseSummary;
  llm_calls: { ts: string; model: string; prompt_version: string; input_tokens: number | null; output_tokens: number | null;
    cost_usd: number | null; latency_ms: number | null; error: string | null }[];
}

export interface Me { name: string; role: "viewer" | "analyst" | "admin"; tenant: string; auth_mode: string }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`/api/v1${path}`, {
    credentials: "same-origin",
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    ...init,
  });
  if (!r.ok) {
    let msg = r.statusText;
    try { const j = await r.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* not json */ }
    throw new ApiError(r.status, msg || `HTTP ${r.status}`);
  }
  return r.json() as Promise<T>;
}

export const api = {
  me: () => call<Me>("/me"),
  overview: () => call<any>("/overview"),
  cases: (params: Record<string, string>) => call<CaseSummary[]>(`/cases?${new URLSearchParams(params)}`),
  case: (id: string) => call<CaseFull>(`/cases/${encodeURIComponent(id)}`),
  verdict: (id: string, body: { verdict: string; note: string; reason: string; suppress: boolean }) =>
    call<CaseFull>(`/cases/${encodeURIComponent(id)}/verdict`, { method: "POST", body: JSON.stringify(body) }),
  action: (id: string, idx: number, op: "approve" | "deny" | "rollback") =>
    call<CaseFull>(`/cases/${encodeURIComponent(id)}/actions/${idx}/${op}`, { method: "POST" }),
  detections: () => call<any[]>("/detections"),
  kb: () => call<any[]>("/kb"),
  kbDoc: (doc: string) => call<{ doc: string; scope: string; text: string }>(`/kb/${encodeURIComponent(doc)}`),
  kbSearch: (q: string) => call<any[]>(`/kb/search?${new URLSearchParams({ q })}`),
  proposals: () => call<any[]>("/proposals"),
  proposal: (id: string) => call<any>(`/proposals/${encodeURIComponent(id)}`),
  review: (id: string, decision: string, note: string) =>
    call<any>(`/proposals/${encodeURIComponent(id)}/review`, { method: "POST", body: JSON.stringify({ decision, note }) }),
  audit: () => call<any[]>("/audit"),
  exclusions: () => call<any[]>("/exclusions"),
  expire: (id: number) => call<any>(`/exclusions/${id}/expire`, { method: "POST" }),
  evalHistory: () => call<any[]>("/eval/history"),
  connectors: () => call<any>("/connectors"),
  run: () => call<{ cases: number; seconds: number }>("/run", { method: "POST" }),
};
