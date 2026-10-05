import { LayoutDashboard, Activity, Server, Shield, AlertTriangle, FileText, Zap } from 'lucide-react';

/*
  Logo: "The Inspection Gate"
  — Three horizontal bars of decreasing width, like a scanner readout
  — A thin vertical line on the left, like a border checkpoint post
  — No letter, no color fill — just white strokes that fade into the dark bg
  — Reads as: scanning, inspection, security checkpoint
*/
function CustomsMark() {
  return (
    <svg className="sb-mark" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      {/* Left post — the checkpoint */}
      <rect x="2" y="4" width="1.5" height="16" rx="0.75" fill="rgba(255,255,255,0.7)" />
      {/* Three scan lines — decreasing opacity, representing layers of inspection */}
      <rect x="6" y="6.5"  width="14" height="1.5" rx="0.75" fill="rgba(255,255,255,0.80)" />
      <rect x="6" y="11.25" width="10" height="1.5" rx="0.75" fill="rgba(255,255,255,0.45)" />
      <rect x="6" y="16"  width="6"  height="1.5" rx="0.75" fill="rgba(255,255,255,0.20)" />
      {/* Small dot on the middle scan line — the "detection" indicator */}
      <circle cx="19" cy="12" r="1.2" fill="rgba(255,255,255,0.6)" />
    </svg>
  );
}

const NAV = [
  { id: 'dashboard', label: 'Overview',          icon: LayoutDashboard, section: 'Monitor' },
  { id: 'activity',  label: 'Agent Activity',    icon: Activity,         section: null },
  { id: 'servers',   label: 'MCP Servers',       icon: Server,           section: 'Configure' },
  { id: 'policies',  label: 'Security Rules',    icon: Shield,           section: null },
  { id: 'threats',   label: 'Threats Caught',    icon: AlertTriangle,    badge: 5, section: null },
  { id: 'audit',     label: 'Decision Log',      icon: FileText,         section: null },
  { id: 'simulator', label: 'Attack Simulator',  icon: Zap,              sim: true, section: 'Try it' },
];

export default function Sidebar({ activePage, setActivePage }) {
  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sb-logo">
        <CustomsMark />
        <div>
          <div className="sb-wordmark">Customs</div>
          <div className="sb-sub">MCP Runtime Security</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="sb-nav">
        {NAV.map((item, i) => {
          const Icon = item.icon;
          const showSection = item.section && (i === 0 || NAV[i - 1].section !== item.section);
          return (
            <div key={item.id}>
              {showSection && <div className="sb-section">{item.section}</div>}
              <div
                className={`sb-item ${activePage === item.id ? 'active' : ''} ${item.sim ? 'sb-sim' : ''}`}
                onClick={() => setActivePage(item.id)}
              >
                <Icon size={13} style={{ opacity: activePage === item.id ? 0.9 : 0.45 }} />
                <span style={{ flex: 1 }}>{item.label}</span>
                {item.badge && <span className="sb-badge">{item.badge}</span>}
              </div>
            </div>
          );
        })}
      </nav>

    </aside>
  );
}
