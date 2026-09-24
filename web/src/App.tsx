import { type ReactNode } from "react";
import { api, type Me } from "./api";
import { href, useRoute } from "./router";
import { ErrorState, Loading, Toasts, useLoad } from "./ui";
import Queue from "./views/Queue";
import CaseView from "./views/CaseView";
import Detections from "./views/Detections";
import Knowledge from "./views/Knowledge";
import Proposals from "./views/Proposals";
import Audit from "./views/Audit";
import Evals from "./views/Evals";
import Settings from "./views/Settings";

const Icon = ({ d }: { d: string }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
    strokeLinejoin="round" aria-hidden><path d={d} /></svg>
);
const ICONS: Record<string, string> = {
  queue: "M4 6h16M4 12h16M4 18h10",
  detections: "M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6z",
  knowledge: "M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5zM4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5",
  proposals: "M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z",
  evals: "M3 3v18h18M7 15l4-4 3 3 5-6",
  audit: "M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.8 1.2V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.8H3a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 2.8-1.2V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.8H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
};

const NAV: [string, string][] = [
  ["queue", "Cases"], ["detections", "Detections"], ["knowledge", "Knowledge"], ["proposals", "Proposals"],
  ["evals", "Evaluation"], ["audit", "Audit Log"], ["settings", "Response"],
];

export default function App() {
  const route = useRoute();
  const me = useLoad<Me>(api.me);
  const ov = useLoad(api.overview, [route[0]]);
  const [section] = route;

  let body: ReactNode;
  if (me.error) body = <div className="page-narrow"><ErrorState error={me.error} retry={me.reload} /></div>;
  else if (!me.data) body = <div className="page"><Loading /></div>;
  else {
    const user = me.data;
    body = {
      queue: <Queue user={user} />,
      case: <CaseView id={route[1]} user={user} />,
      detections: <Detections />,
      knowledge: <Knowledge doc={route[1]} />,
      proposals: <Proposals id={route[1]} user={user} />,
      evals: <Evals />,
      audit: <Audit />,
      settings: <Settings />,
    }[section] ?? <Queue user={user} />;
  }

  const active = section === "case" ? "queue" : section;
  return (
    <div className="shell">
      <nav className="nav" aria-label="Main">
        <div className="brand">
          <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden>
            {/* watchtower: searchlight beam, cab, legs */}
            <path d="M3 4 13 11h6L29 4z" fill="var(--searchlight)" opacity="0.35" />
            <rect x="11" y="10" width="10" height="5" rx="1" fill="var(--accent)" />
            <path d="M10 15h12M12 15l-3 15M20 15l3 15M11 22h10" stroke="var(--text-muted)" strokeWidth="2" fill="none" />
          </svg>
          Warden
        </div>
        {NAV.map(([k, label]) => (
          <a key={k} href={href(k)} aria-current={active === k ? "page" : undefined}>
            <Icon d={ICONS[k]} />{label}
            {k === "queue" && ov.data?.awaiting_approval > 0 &&
              <span className="badge" title={`${ov.data.awaiting_approval} need approval`}>{ov.data.awaiting_approval}</span>}
          </a>
        ))}
      </nav>
      <main className="main" id="main">{body}</main>
      <Toasts />
    </div>
  );
}
