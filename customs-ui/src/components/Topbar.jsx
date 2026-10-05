import { ChevronRight } from 'lucide-react';

const LABELS = {
  dashboard: 'Dashboard',
  activity: 'Agent Activity',
  servers: 'MCP Servers',
  policies: 'Policies',
  threats: 'Threats',
  audit: 'Audit Log',
  simulator: 'Attack Simulator',
};

export default function Topbar({ activePage, customsEnabled, setCustomsEnabled }) {
  return (
    <header className="topbar">
      <div className="tb-crumb">
        <span>Customs</span>
        <span className="tb-crumb-sep"><ChevronRight size={11} /></span>
        <span className="tb-crumb-cur">{LABELS[activePage] || 'Dashboard'}</span>
      </div>

      <div className="tb-right">
        <div
          className={`customs-pill ${customsEnabled ? 'on' : 'off'}`}
          onClick={() => setCustomsEnabled(!customsEnabled)}
          title="Toggle Customs enforcement"
        >
          <span className="dot" style={{
            width: 6, height: 6,
            background: customsEnabled ? 'var(--green)' : 'var(--red)',
          }} />
          Customs {customsEnabled ? 'ON' : 'OFF'}
          <label className="toggle" style={{ pointerEvents: 'none', marginLeft: 2 }}>
            <input type="checkbox" checked={customsEnabled} onChange={() => {}} />
            <div className="toggle-track" />
            <div className="toggle-thumb" />
          </label>
        </div>
      </div>
    </header>
  );
}
