import { useState } from 'react';
import { Lock } from 'lucide-react';

const POLICIES = [
  {
    id: 'p1', from: 'SECRET', to: 'PUBLIC', action: 'BLOCK', cp: 1,
    desc: 'Credentials, API keys, or private data must never reach public destinations such as GitHub Issues, Gists, or public APIs.',
    enabled: true,
  },
  {
    id: 'p2', from: 'SECRET', to: 'EXTERNAL', action: 'BLOCK', cp: 1,
    desc: 'Secret data attempted to leave to an external SaaS endpoint. Blocked unless explicitly whitelisted.',
    enabled: true,
  },
  {
    id: 'p3', from: 'UNRELATED ACTION', to: 'EXTERNAL EFFECT', action: 'BLOCK', cp: 1,
    desc: 'Tool action has no relevance to the current task context, yet produces an outbound side effect.',
    enabled: true,
  },
  {
    id: 'p4', from: 'CREDENTIAL ACCESS', to: 'UNNECESSARY TASK', action: 'WARN', cp: 1,
    desc: 'Agent is accessing credential files when the declared task does not require authentication or secrets.',
    enabled: true,
  },
  {
    id: 'p5', from: 'UNDECLARED RECIPIENT', to: 'NETWORK', action: 'BLOCK', cp: 2,
    desc: "MCP server introduced an email address, webhook, or recipient not present in the agent's declared tool call arguments.",
    enabled: true,
  },
  {
    id: 'p6', from: 'UNDECLARED HOST', to: 'NETWORK', action: 'BLOCK', cp: 2,
    desc: 'MCP server made a request to a hostname absent from declared arguments and absent from the server baseline configuration.',
    enabled: true,
  },
  {
    id: 'p7', from: 'UNEXPECTED FILE READ', to: 'ANY', action: 'WARN', cp: 2,
    desc: 'MCP server read a file outside the declared working directory or not referenced in the call arguments.',
    enabled: true,
  },
  {
    id: 'p8', from: 'PAYLOAD MATCHES SECRET FILE', to: 'NETWORK', action: 'BLOCK', cp: 2,
    desc: 'Outbound request payload contains content matching a secret file read during the same call window.',
    enabled: true, critical: true,
  },
];

const ACTION_PILL = { BLOCK: 'pill-red', WARN: 'pill-amber', ALLOW: 'pill-green' };

export default function Policies() {
  const [pols, setPols] = useState(POLICIES);

  const toggle = id => setPols(prev => prev.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));

  const cp1 = pols.filter(p => p.cp === 1);
  const cp2 = pols.filter(p => p.cp === 2);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="sec-head">
        <div>
          <div className="sec-title">Security Policies</div>
          <div className="sec-sub">Deterministic rules applied at each checkpoint — no ML required</div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <span className="pill pill-green">{pols.filter(p => p.enabled).length} active</span>
          <span className="pill pill-ghost">{pols.filter(p => !p.enabled).length} disabled</span>
        </div>
      </div>

      <PolicyGroup label="Checkpoint 1 — Call Firewall" cp={1} color="var(--accent)" desc="Applied before forwarding to the MCP server. Evaluates declared arguments, task context, and data classification." policies={cp1} onToggle={toggle} />
      <PolicyGroup label="Checkpoint 2 — Effect Customs" cp={2} color="var(--green)" desc="Applied after MCP server executes. Reconciles actual network and filesystem effects against declared intent." policies={cp2} onToggle={toggle} />
    </div>
  );
}

function PolicyGroup({ label, cp, color, desc, policies, onToggle }) {
  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      {/* Group header */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-2)', display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ width: 20, height: 20, borderRadius: '50%', background: color, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: '#fff', flexShrink: 0, marginTop: 1 }}>
          {cp}
        </div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--t-1)', letterSpacing: '-0.01em' }}>{label}</div>
          <div style={{ fontSize: 11, color: 'var(--t-3)', marginTop: 2, lineHeight: 1.5 }}>{desc}</div>
        </div>
      </div>

      {/* Policies */}
      <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {policies.map(p => (
          <div
            key={p.id}
            className="pol-item"
            style={p.critical ? { borderColor: 'var(--red-bd)', background: 'var(--red-bg)' } : {}}
          >
            {/* Rule expression */}
            <div className="pol-expr">
              {p.critical && <Lock size={10} color="var(--red-text)" style={{ flexShrink: 0 }} />}
              <span className="pol-token">{p.from}</span>
              <span className="pol-arrow">→</span>
              <span className="pol-token">{p.to}</span>
            </div>

            {/* Description */}
            <div className="pol-desc">{p.desc}</div>

            {/* Action + toggle */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
              <span className={`pill ${ACTION_PILL[p.action]}`}>{p.action}</span>
              <label className="toggle">
                <input type="checkbox" checked={p.enabled} onChange={() => onToggle(p.id)} />
                <div className="toggle-track" />
                <div className="toggle-thumb" />
              </label>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
