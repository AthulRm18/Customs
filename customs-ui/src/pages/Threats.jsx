import { AlertTriangle, FileWarning, Zap, Eye, Mail, ShieldCheck } from 'lucide-react';

const THREATS = [
  {
    id: 't1', icon: Mail, severity: 'HIGH', cp: 2,
    name: 'Compromised Email Server',
    plain: 'The email server secretly copied every message to an attacker, without the AI agent knowing.',
    howCaught: 'Customs saw ghost@evil.io in the outbound request — it was never in the agent\'s original call. Dropped.',
    effects: ['Undeclared BCC: ghost@evil.io', 'Effect inspection (Checkpoint 2)', 'Zero data left the machine'],
    status: 'BLOCKED', scenario: 'Scenario 1',
  },
  {
    id: 't2', icon: FileWarning, severity: 'CRITICAL', cp: 1,
    name: 'AWS Credential Theft',
    plain: 'Agent read a credentials file while fixing a bug, then tried to post the AWS key to a public GitHub issue.',
    howCaught: 'Call Firewall detected a secret (AWS key) heading to a public destination. Blocked before GitHub was contacted.',
    effects: ['AWS_SECRET_ACCESS_KEY in request body', 'Destination: public GitHub issue', 'Policy: secret → public = always block'],
    status: 'BLOCKED', scenario: 'Scenario 2',
  },
  {
    id: 't3', icon: Zap, severity: 'HIGH', cp: 1,
    name: 'Hidden Instructions in a Webpage',
    plain: 'A malicious webpage contained invisible instructions hijacking the agent to steal credentials — even though the task was just "summarize this page".',
    howCaught: 'Task said summarize. Agent tried to read credentials. Mismatch = prompt injection. Blocked.',
    effects: ['Task: summarize webpage', 'Actual attempt: read .env + upload', 'Zero credential exposure'],
    status: 'BLOCKED', scenario: 'Scenario 3',
  },
  {
    id: 't4', icon: Eye, severity: 'CRITICAL', cp: 2,
    name: 'Lying "Read-Only" Tool',
    plain: 'A weather tool claimed to be read-only and harmless. It secretly read AWS credentials and tried to send them to an attacker\'s server.',
    howCaught: 'Customs saw the file read + outbound POST. Payload matched the credential file content. CRITICAL — dropped.',
    effects: ['Read: .aws/credentials (unexpected)', 'POST to evil.example (new host)', 'Payload = credential file content'],
    status: 'BLOCKED', scenario: 'Scenario 4',
  },
  {
    id: 't5', icon: Mail, severity: 'HIGH', cp: 2,
    name: 'Undeclared Recipient Detection',
    plain: 'Any email address or webhook URL that appears in a server\'s outbound request but was never mentioned by the agent is automatically blocked.',
    howCaught: 'Declared recipients vs actual recipients — any undeclared address in the outbound request is automatically dropped.',
    effects: ['Applies to all email, webhook, API calls', 'No machine learning required', 'Zero false negatives on undeclared data'],
    status: 'ACTIVE DETECTION', scenario: 'Ongoing',
  },
];

const SEV = {
  CRITICAL: { pill: 'pill-red', iconClass: 'critical' },
  HIGH:     { pill: 'pill-amber', iconClass: 'high' },
};

export default function Threats() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* Header */}
      <div className="sec-head">
        <div>
          <div className="sec-title">Threats Detected</div>
          <div className="sec-sub">Real attacks Customs intercepted across the demo scenarios</div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <span className="pill pill-red">2 critical</span>
          <span className="pill pill-amber">3 high</span>
        </div>
      </div>

      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr) 1fr', gap: 1, background: 'var(--border)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        {[
          { label: 'Caught before execution', val: 2, note: 'Blocked at Checkpoint 1 — server never ran', color: 'var(--accent)' },
          { label: 'Caught during execution', val: 3, note: 'Blocked at Checkpoint 2 — server effect dropped', color: 'var(--green)' },
          { label: 'Credentials protected', val: 4, note: 'AWS keys, .env files — none escaped', color: 'var(--t-1)' },
        ].map(s => (
          <div key={s.label} style={{ background: 'var(--bg-1)', padding: '16px 18px' }}>
            <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.07em', textTransform: 'uppercase', color: 'var(--t-4)', marginBottom: 6 }}>{s.label}</div>
            <div style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.04em', color: s.color, lineHeight: 1 }}>{s.val}</div>
            <div style={{ fontSize: 11, color: 'var(--t-4)', marginTop: 4 }}>{s.note}</div>
          </div>
        ))}
        <div style={{ background: 'var(--green-bg)', borderLeft: '1px solid var(--green-bd)', padding: '16px 18px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <ShieldCheck size={14} color="var(--green)" />
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--green)' }}>All contained</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--t-3)' }}>Zero bytes of attacker-intended data left the machine</div>
        </div>
      </div>

      {/* Threat list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {THREATS.map(t => {
          const Icon = t.icon;
          const sv = SEV[t.severity] || SEV.HIGH;
          return (
            <div
              key={t.id}
              className="threat-card"
              style={t.severity === 'CRITICAL' ? { borderColor: 'var(--red-bd)' } : {}}
            >
              <div className={`threat-icon ${sv.iconClass}`}><Icon size={16} /></div>
              <div style={{ flex: 1 }}>
                <div className="threat-name">{t.name}</div>
                {/* Plain English description — no jargon */}
                <div className="threat-desc" style={{ marginBottom: 6 }}>{t.plain}</div>
                {/* How Customs caught it */}
                <div style={{ fontSize: 11, color: 'var(--t-3)', fontStyle: 'italic', marginBottom: 8 }}>
                  <span style={{ fontStyle: 'normal', fontWeight: 600, color: 'var(--green)', marginRight: 4 }}>How caught:</span>
                  {t.howCaught}
                </div>
                <div className="threat-tags">
                  {t.effects.map((e, i) => <span key={i} className="tag">{e}</span>)}
                </div>
              </div>
              <div className="threat-meta">
                <span className={`pill ${sv.pill}`}>{t.severity}</span>
                <span className="pill pill-ghost" style={{ fontSize: 9 }}>
                  {t.cp === 1 ? 'Checkpoint 1' : 'Checkpoint 2'}
                </span>
                <span className="pill pill-red" style={{ fontSize: 9 }}>{t.status}</span>
                <span className="pill pill-blue" style={{ fontSize: 9 }}>{t.scenario}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* What makes this possible */}
      <div style={{ padding: 16, borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-1)' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t-1)', marginBottom: 8 }}>
          How Customs catches these
        </div>
        <div style={{ fontSize: 11, color: 'var(--t-3)', lineHeight: 1.7 }}>
          Every MCP tool call passes through two checkpoints. <strong style={{ color: 'var(--t-1)' }}>Checkpoint 1</strong> inspects the agent's request before it runs — catching bad intent.
          <strong style={{ color: 'var(--t-1)' }}> Checkpoint 2</strong> watches what the server <em>actually does</em> at runtime — catching compromised servers that act beyond what was requested.
          Together, they close the gap between what an AI agent asks for and what actually happens on your system.
        </div>
      </div>
    </div>
  );
}
