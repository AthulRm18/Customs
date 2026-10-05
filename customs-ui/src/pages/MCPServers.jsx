import { HardDrive, GitBranch, Mail, Globe, CheckCircle } from 'lucide-react';

const SERVERS = [
  {
    id: 'filesystem', name: 'Filesystem MCP', icon: HardDrive,
    status: 'running', risk: 'MEDIUM',
    tools: ['read_file', 'write_file', 'run_tests'],
    last: '2s ago', calls: 68, blocked: 1,
    desc: 'In-memory virtual filesystem. Monitors all file reads and writes against declared task scope.',
  },
  {
    id: 'github', name: 'GitHub MCP', icon: GitBranch,
    status: 'running', risk: 'HIGH',
    tools: ['search_repo', 'create_issue', 'create_pr'],
    last: '12s ago', calls: 24, blocked: 3,
    desc: 'Simulated GitHub API. High risk — public destination. Blocks all SECRET data exfiltration attempts.',
  },
  {
    id: 'mailer', name: 'Mailer MCP', icon: Mail,
    status: 'paused', risk: 'HIGH',
    tools: ['send_email'],
    last: 'Just now', calls: 8, blocked: 2,
    desc: 'Compromised in Scenario 1. Secretly injects BCC recipients. Suspended after Checkpoint 2 detected the undeclared effect.',
    compromised: true,
  },
  {
    id: 'browser', name: 'Browser MCP', icon: Globe,
    status: 'running', risk: 'MEDIUM',
    tools: ['fetch', 'get_weather'],
    last: '45s ago', calls: 24, blocked: 1,
    desc: 'Compromised in Scenario 4. Despite readOnlyHint: true, attempted to read .aws/credentials and POST to external webhook.',
  },
];

const RISK_COLOR = { LOW: 'var(--green)', MEDIUM: 'var(--amber)', HIGH: 'var(--red-text)', CRITICAL: 'var(--red-text)' };

export default function MCPServers() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="sec-head">
        <div>
          <div className="sec-title">MCP Servers</div>
          <div className="sec-sub">All servers monitored at runtime by Customs</div>
        </div>
        <span className="pill pill-ghost">4 connected</span>
      </div>

      <div className="srv-grid">
        {SERVERS.map(s => {
          const Icon = s.icon;
          return (
            <div
              key={s.id}
              className="srv-card"
              style={s.compromised ? { borderColor: 'var(--amber-bd)' } : {}}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
                <div className="srv-icon"><Icon size={15} /></div>
                <span className={`pill ${s.status === 'running' ? 'pill-green' : 'pill-amber'}`} style={{ fontSize: 9 }}>
                  {s.status}
                </span>
              </div>

              <div style={{ marginBottom: 6, display: 'flex', alignItems: 'center', gap: 7 }}>
                <div className="srv-name">{s.name}</div>
                {s.compromised && <span className="pill pill-amber" style={{ fontSize: 9 }}>compromised</span>}
              </div>

              <p style={{ fontSize: 11, color: 'var(--t-3)', lineHeight: 1.5, marginBottom: 10 }}>{s.desc}</p>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 12 }}>
                {s.tools.map(t => <span key={t} className="tag">{t}</span>)}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                {[
                  { k: 'Risk', v: s.risk, c: RISK_COLOR[s.risk] },
                  { k: 'Total calls', v: s.calls, c: null },
                  { k: 'Blocked', v: s.blocked, c: s.blocked > 0 ? 'var(--red-text)' : null },
                  { k: 'Last activity', v: s.last, c: null },
                ].map(row => (
                  <div key={row.k} className="srv-row">
                    <span className="srv-key">{row.k}</span>
                    <span className="srv-val" style={row.c ? { color: row.c } : {}}>{row.v}</span>
                  </div>
                ))}
                <div className="srv-row">
                  <span className="srv-key">Customs</span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--green)', fontWeight: 600 }}>
                    <CheckCircle size={10} />Protected
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Architecture strip */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t-1)', marginBottom: 14, letterSpacing: '-0.01em' }}>
          Two-checkpoint model
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {[
            { num: 1, name: 'Call Firewall', color: 'var(--accent)', desc: 'Evaluates the declared tool call before it reaches the MCP server. Checks arguments, destinations, detected secrets, and task relevance.' },
            { num: 2, name: 'Effect Customs', color: 'var(--green)', desc: 'Observes every network request and file read produced during execution. Reconciles actual effects against declared intent and drops undeclared ones.' },
          ].map(cp => (
            <div key={cp.num} style={{ padding: 14, borderRadius: 'var(--r-md)', border: '1px solid var(--border)', background: 'var(--bg-2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ width: 20, height: 20, borderRadius: '50%', background: cp.color, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: '#fff', flexShrink: 0 }}>
                  {cp.num}
                </span>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--t-1)' }}>Checkpoint {cp.num} — {cp.name}</span>
              </div>
              <p style={{ fontSize: 11, color: 'var(--t-3)', lineHeight: 1.6 }}>{cp.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
