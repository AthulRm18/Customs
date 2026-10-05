import { useState } from 'react';
import { CheckCircle, XCircle, AlertTriangle, ChevronRight } from 'lucide-react';

const LOG = [
  { id: 'c001', time: '00:13:38', tool: 'filesystem.read_file', cp: 'CP1', data: 'src/auth.js',                       dest: 'LOCAL',    risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c002', time: '00:13:39', tool: 'filesystem.read_file', cp: 'CP1', data: 'src/login.js',                      dest: 'LOCAL',    risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c003', time: '00:13:40', tool: 'filesystem.run_tests', cp: 'CP1', data: '—',                                 dest: 'LOCAL',    risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c004', time: '00:13:41', tool: 'filesystem.read_file', cp: 'CP1', data: '.env (SECRET)',                     dest: 'LOCAL',    risk: 'MEDIUM',   dec: 'WARN'  },
  { id: 'c005', time: '00:13:42', tool: 'mailer.send_email',    cp: 'CP1', data: 'alice@acme.com',                    dest: 'EXTERNAL', risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c006', time: '00:13:42', tool: 'mailer.send_email ⚡', cp: 'CP2', data: 'ghost@evil.io (BCC undeclared)',    dest: 'EXTERNAL', risk: 'HIGH',     dec: 'BLOCK' },
  { id: 'c007', time: '00:13:55', tool: 'github.create_issue',  cp: 'CP1', data: 'AWS_SECRET_ACCESS_KEY',             dest: 'PUBLIC',   risk: 'CRITICAL', dec: 'BLOCK' },
  { id: 'c008', time: '00:14:00', tool: 'browser.fetch',        cp: 'CP1', data: 'https://webpage.example',          dest: 'EXTERNAL', risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c009', time: '00:14:01', tool: 'filesystem.read_file', cp: 'CP1', data: 'src/app.js',                        dest: 'LOCAL',    risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c010', time: '00:14:02', tool: 'browser.get_weather',  cp: 'CP1', data: 'city: Bengaluru',                  dest: 'EXTERNAL', risk: 'LOW',      dec: 'ALLOW' },
  { id: 'c011', time: '00:14:02', tool: 'browser.get_weather ⚡', cp: 'CP2', data: '.aws/credentials + evil.example', dest: 'EXTERNAL', risk: 'CRITICAL', dec: 'BLOCK' },
  { id: 'c012', time: '00:14:15', tool: 'github.search_repo',   cp: 'CP1', data: 'query: auth bug',                  dest: 'PRIVATE',  risk: 'LOW',      dec: 'ALLOW' },
];

const RISK_PILL = { LOW: 'pill-ghost', MEDIUM: 'pill-amber', HIGH: 'pill-red', CRITICAL: 'pill-red' };
const FILTERS = ['ALL', 'ALLOWED', 'WARNINGS', 'BLOCKED', 'CRITICAL'];

export default function AuditLog() {
  const [filter, setFilter] = useState('ALL');
  const [selected, setSelected] = useState(null);

  const rows = LOG.filter(e => {
    if (filter === 'ALLOWED') return e.dec === 'ALLOW';
    if (filter === 'WARNINGS') return e.dec === 'WARN';
    if (filter === 'BLOCKED') return e.dec === 'BLOCK';
    if (filter === 'CRITICAL') return e.risk === 'CRITICAL';
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="sec-head">
        <div>
          <div className="sec-title">Audit Log</div>
          <div className="sec-sub">Immutable record of all security decisions</div>
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

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 320px' : '1fr', gap: 16, alignItems: 'start' }}>
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Time</th>
                <th>Call ID</th>
                <th>Tool</th>
                <th>CP</th>
                <th>Data</th>
                <th>Dest</th>
                <th>Risk</th>
                <th>Decision</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map(e => (
                <tr
                  key={e.id}
                  style={{ cursor: 'pointer', background: selected?.id === e.id ? 'var(--bg-hover)' : undefined }}
                  onClick={() => setSelected(selected?.id === e.id ? null : e)}
                >
                  <td><span className="mono">{e.time}</span></td>
                  <td><span className="tag">{e.id}</span></td>
                  <td><span className="mono">{e.tool}</span></td>
                  <td><span className={`pill ${e.cp === 'CP2' ? 'pill-ghost' : 'pill-blue'}`} style={{ fontSize: 9 }}>{e.cp}</span></td>
                  <td style={{ maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span className="mono" style={{ color: 'var(--t-3)' }}>{e.data}</span>
                  </td>
                  <td><span className="tag">{e.dest}</span></td>
                  <td><span className={`pill ${RISK_PILL[e.risk]}`} style={{ fontSize: 9 }}>{e.risk}</span></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      {e.dec === 'ALLOW' && <CheckCircle size={11} color="var(--green)" />}
                      {e.dec === 'WARN'  && <AlertTriangle size={11} color="var(--amber)" />}
                      {e.dec === 'BLOCK' && <XCircle size={11} color="var(--red-text)" />}
                      <span style={{ fontSize: 11, fontWeight: 600, color: e.dec === 'ALLOW' ? 'var(--green)' : e.dec === 'WARN' ? 'var(--amber)' : 'var(--red-text)' }}>
                        {e.dec}
                      </span>
                    </div>
                  </td>
                  <td>
                    <ChevronRight size={11} color="var(--t-4)" style={{ transform: selected?.id === e.id ? 'rotate(90deg)' : 'none', transition: '160ms' }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Effect receipt sidebar */}
        {selected && (
          <div className="card fade-in" style={{ padding: 16, position: 'sticky', top: 64 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t-1)', marginBottom: 14, letterSpacing: '-0.01em' }}>
              Effect Receipt
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
              {[
                { k: 'Call ID', v: selected.id, mono: true },
                { k: 'Tool', v: selected.tool, mono: true },
                { k: 'Checkpoint', v: selected.cp },
                { k: 'Risk', v: selected.risk },
                { k: 'Data', v: selected.data, mono: true },
                { k: 'Destination', v: selected.dest },
              ].map(f => (
                <div key={f.k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                  <span style={{ fontSize: 11, color: 'var(--t-4)', flexShrink: 0 }}>{f.k}</span>
                  <span style={{ fontSize: 11, fontFamily: f.mono ? 'var(--mono)' : undefined, color: 'var(--t-1)', textAlign: 'right', maxWidth: 180, wordBreak: 'break-all' }}>
                    {f.v}
                  </span>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
              <div
                style={{
                  padding: '9px 11px',
                  borderRadius: 'var(--r-md)',
                  background: selected.dec === 'ALLOW' ? 'var(--green-bg)' : selected.dec === 'WARN' ? 'var(--amber-bg)' : 'var(--red-bg)',
                  border: `1px solid ${selected.dec === 'ALLOW' ? 'var(--green-bd)' : selected.dec === 'WARN' ? 'var(--amber-bd)' : 'var(--red-bd)'}`,
                  fontSize: 11,
                  fontWeight: 600,
                  color: selected.dec === 'ALLOW' ? 'var(--green)' : selected.dec === 'WARN' ? 'var(--amber)' : 'var(--red-text)',
                  lineHeight: 1.5,
                }}
              >
                {selected.dec === 'ALLOW' && '✓ Permitted — no policy violations'}
                {selected.dec === 'WARN' && '⚠ Warning — unusual access pattern, allowed but flagged'}
                {selected.dec === 'BLOCK' && '✗ Blocked — policy violation, request dropped'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
