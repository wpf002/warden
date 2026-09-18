import { useMemo, useState, type ReactNode } from "react";
import { api } from "../api";
import { href } from "../router";
import { Empty, ErrorState, Loading, titleCase, useLoad } from "../ui";

const KINDS = ["all", "playbook", "policy", "incident", "learned", "mitre"];

export default function Knowledge({ doc }: { doc?: string }) {
  const list = useLoad(api.kb);
  const [kind, setKind] = useState("all");
  const [q, setQ] = useState("");
  const rows = useMemo(() => (list.data ?? []).filter((d) =>
    (kind === "all" || d.kind === kind) && (!q || `${d.doc} ${d.title}`.toLowerCase().includes(q.toLowerCase()))), [list.data, kind, q]);
  return (
    <div className="page">
      <div className="page-head">
        <h1>Knowledge</h1>
      </div>
      <div className="grid-main" style={{ gridTemplateColumns: "minmax(0, 320px) minmax(0, 1fr)", alignItems: "stretch", height: "calc(100vh - 136px)" }}>
        <section className="card card-flush" style={{ display: "flex", flexDirection: "column", minHeight: 0 }}>
          <div className="card-head" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <input className="input" type="search" placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter documents" />
            <div className="row-wrap">{KINDS.map((k) => (
              <button key={k} className="tab" aria-selected={kind === k} onClick={() => setKind(k)}>{titleCase(k === "mitre" ? "ATT&CK" : k)}</button>
            ))}</div>
          </div>
          {list.error ? <div style={{ padding: 16 }}><ErrorState error={list.error} /></div>
            : !list.data ? <div style={{ padding: 16 }}><Loading /></div>
            : rows.length === 0 ? <Empty title="No Documents" />
            : (
              <nav style={{ flex: 1, overflow: "auto" }} aria-label="Documents">
                {rows.map((d) => (
                  <a key={`${d.scope}:${d.doc}`} href={href(`knowledge/${d.doc}`)} aria-current={doc === d.doc ? "page" : undefined}
                    style={{ display: "block", padding: "8px 16px", borderBottom: "1px solid var(--border)", textDecoration: "none",
                      background: doc === d.doc ? "var(--accent-soft)" : undefined }}>
                    <div className="ellipsis" style={{ color: "var(--text)", fontSize: 14 }}>{d.title}</div>
                    <div className="row small faint"><span>{titleCase(d.kind)}</span>{d.scope !== "global" && <span className="tag">Tenant</span>}</div>
                  </a>
                ))}
              </nav>
            )}
        </section>
        <section className="card" style={{ overflow: "auto", minHeight: 0 }}>{doc ? <Doc doc={doc} /> : <Empty title="Select a Document" />}</section>
      </div>
    </div>
  );
}

function Doc({ doc }: { doc: string }) {
  const d = useLoad(() => api.kbDoc(doc), [doc]);
  if (d.error) return <ErrorState error={d.error} />;
  if (!d.data) return <Loading rows={12} />;
  return <article className="prose">{renderMarkdown(d.data.text)}<p className="small faint mono">{doc}.md</p></article>;
}

// Minimal markdown to React elements: headings, lists, paragraphs, inline code. Never raw HTML.
function inline(s: string): ReactNode[] {
  return s.split(/(`[^`]+`)/g).map((p, i) => p.startsWith("`") ? <code key={i}>{p.slice(1, -1)}</code> : p);
}
function renderMarkdown(md: string): ReactNode[] {
  const out: ReactNode[] = [];
  const lines = md.split("\n");
  let list: { ordered: boolean; items: string[] } | null = null;
  let para: string[] = [];
  const flush = () => {
    if (para.length) { out.push(<p key={out.length}>{inline(para.join(" "))}</p>); para = []; }
    if (list) {
      const items = list.items.map((t, i) => <li key={i}>{inline(t)}</li>);
      out.push(list.ordered ? <ol key={out.length}>{items}</ol> : <ul key={out.length}>{items}</ul>);
      list = null;
    }
  };
  for (const ln of lines) {
    const h = /^(#{1,3})\s+(.*)/.exec(ln);
    const li = /^\s*(?:[-*]|(\d+)\.)\s+(.*)/.exec(ln);
    if (h) { flush(); const L = `h${h[1].length + 1}` as "h2" | "h3" | "h4"; out.push(<L key={out.length}>{inline(h[2])}</L>); }
    else if (li) { if (para.length) flush(); const ordered = !!li[1]; if (!list || list.ordered !== ordered) { flush(); list = { ordered, items: [] }; } list.items.push(li[2]); }
    else if (!ln.trim()) flush();
    else { if (list) flush(); para.push(ln.trim()); }
  }
  flush();
  return out;
}
