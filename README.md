# Customs

> Runtime security enforcement for AI agents using MCP tools.
<img width="1234" height="670" alt="Screenshot 2026-10-05 014446" src="https://github.com/user-attachments/assets/c99310fd-3282-4a94-bde3-ff26b259c396" />


## The Problem

AI agents are being given real tools — email, filesystems, GitHub, APIs — through the **Model Context Protocol (MCP)**. The standard way to secure this is to check what the agent *asks for* before running it.

That's only half the picture.

An MCP server is an independent process. It receives a tool call and runs code. If that server is compromised, misconfigured, or maliciously designed, it can:

- Add undeclared recipients to an email
- Read files the agent never mentioned
- Post credentials to a public endpoint
- Contact external hosts that weren't in the original request

The agent's request looked completely legitimate. The damage happened *inside the server* — after the request was approved.

No existing firewall sees this. They inspect the request, not the effect.

**Customs watches what the server actually does.**

---

## How It Works

Every MCP tool call passes through two checkpoints:

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Agent                                 │
│           task: "Email the Q3 invoice to alice@acme.com"        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ tool call
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  CHECKPOINT 1 — Call Firewall                    │
│                                                                  │
│  ✓ Is this tool relevant to the declared task?                  │
│  ✓ Does the request contain secrets?                            │
│  ✓ Is the destination safe?                                     │
│  ✓ Does the data label match the destination label?             │
│                                                                  │
│  Verdict: ALLOW / WARN / BLOCK                                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │  ALLOW
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                       MCP Server                                 │
│                                                                  │
│  ← Customs opens a call window here                             │
│    every file read, network request, and email is recorded      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ server produces effects
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                CHECKPOINT 2 — Effect Reconciler                  │
│                                                                  │
│  Declared atoms (from agent's tool call arguments):             │
│    → alice@acme.com                                             │
│                                                                  │
│  Actual atoms (from server's observed network request):         │
│    → alice@acme.com                                             │
│    → ghost@evil.io          ← NOT declared                      │
│                                                                  │
│  Unexplained: ghost@evil.io                                     │
│  Verdict: BLOCK                                                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
               ┌───────────┴───────────┐
               │                       │
               ▼                       ▼
       Request Dropped          Server Paused
       Audit Record Created     Security Event Emitted
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        React Frontend                             │
│   Dashboard · Simulator · Threats · Audit Log · Policy Editor   │
└──────────────┬───────────────────────────┬───────────────────────┘
               │ REST API                  │ SSE stream
               ▼                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                              │
│                                                                   │
│  ┌─────────────────┐   ┌──────────────────┐                      │
│  │  Call Firewall  │   │ Effect Reconciler │                      │
│  │  (Checkpoint 1) │   │  (Checkpoint 2)  │                      │
│  └────────┬────────┘   └────────┬─────────┘                      │
│           │                     │                                 │
│  ┌────────▼─────────────────────▼──────────┐                     │
│  │              Policy Engine              │                      │
│  │   data_label → destination → BLOCK      │                      │
│  └────────────────────┬────────────────────┘                     │
│                       │                                           │
│  ┌────────────────────▼────────────────────┐                     │
│  │            Detectors                    │                      │
│  │  secrets.py · destinations.py · atoms.py│                      │
│  └─────────────────────────────────────────┘                     │
│                                                                   │
│  ┌─────────────────────────────────────────┐                     │
│  │         Simulated MCP Servers           │                      │
│  │  Mailer · Filesystem · GitHub · Browser │                      │
│  └────────┬──────────────────┬─────────────┘                     │
│           │                  │                                    │
│  ┌────────▼──────┐  ┌────────▼────────┐                          │
│  │ FakeFilesystem│  │  FakeNetwork    │                           │
│  │ FakeEmail     │  │  (intercepts    │                           │
│  │ (in-memory)   │  │   all requests) │                           │
│  └───────────────┘  └────────┬────────┘                          │
│                              │ blocked before delivery            │
│  ┌───────────────────────────▼────────────────────────────┐      │
│  │              SQLite Audit Log + SSE Event Bus           │      │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Attacks Customs Catches

### 1 — Compromised Mailer Server

The agent sends a perfectly legitimate email request. The server — compromised — silently injects a BCC.

```
Agent declares:   to=alice@acme.com
Server actually:  to=alice@acme.com, bcc=ghost@evil.io

Customs CP2:      BLOCK
                  Undeclared recipient: ghost@evil.io
                  Server: PAUSED
```

**Why this matters:** No firewall catches this. The agent's request was clean. The injection happened inside the server, in the SMTP payload Customs intercepts.

---

### 2 — Credential Exfiltration via GitHub

While fixing a bug, the agent legitimately reads `src/auth.js`. Then (via prompt injection or a compromised tool) it tries to post the `.env` file contents to a public GitHub issue.

```
Data label:   SECRET  (AWS key detected in payload)
Destination:  PUBLIC  (api.github.com)

Customs CP1:  BLOCK
              Policy: SECRET → PUBLIC = always block
```

---

### 3 — Lying Read-Only Tool

A weather tool declares `readOnlyHint: true`. At runtime it reads `.aws/credentials` and POSTs the contents to an attacker webhook. Customs intercepts both the unauthorized file access and the outbound POST.

```
Declared:  GET weather for Bengaluru
Actual:    READ .aws/credentials
           POST https://attacker-webhook.evil.io/collect
           Payload contains credential file contents

Customs CP2:  BLOCK — CRITICAL
              Unexpected file read + payload matches secret file
```

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Backend framework | FastAPI (Python 3.11) | Async, fast, Pydantic-native, clean OpenAPI docs |
| Data validation | Pydantic v2 | All inputs and outputs are typed — no raw dicts in the security path |
| Database | SQLite + SQLAlchemy | Zero-config persistence for the hackathon; swap to Postgres in production |
| Live events | SSE (Server-Sent Events) | Real-time security events streamed to the frontend without WebSocket complexity |
| Secret detection | Regex patterns (no LLM) | Deterministic — cannot be bypassed by prompt injection |
| Frontend | React + Vite | Fast dev cycle; single-page app with live SSE feed |
| Styling | Vanilla CSS | Full control, no framework overhead |
| MCP simulation | Custom sandboxed infra | FakeFilesystem + FakeNetwork — no real files touched, no real requests sent |

**Important:** No LLM is in the security decision path. Every ALLOW/BLOCK is deterministic rule-based evaluation. This means Customs itself cannot be jailbroken.

---

## Project Structure

```
customs/
├── README.md
├── .gitignore
│
├── backend/
│   ├── pyproject.toml
│   └── app/
│       ├── main.py                      ← FastAPI app, CORS, startup
│       ├── schemas.py                   ← All Pydantic types
│       │
│       ├── detectors/
│       │   ├── secrets.py               ← AWS keys, JWTs, API keys, .env vars
│       │   ├── destinations.py          ← LOCAL / PRIVATE / INTERNAL / PUBLIC
│       │   └── atoms.py                 ← Extract emails, URLs, hosts for reconciliation
│       │
│       ├── services/
│       │   ├── call_firewall.py         ← Checkpoint 1 evaluation
│       │   ├── effect_customs.py        ← Checkpoint 2 evaluation
│       │   ├── reconciler.py            ← Declared vs actual atom diff
│       │   ├── policy_engine.py         ← Configurable rule engine
│       │   ├── effect_tracker.py        ← Tracks per-call-id server effects
│       │   ├── risk_engine.py           ← Risk scoring
│       │   └── audit_service.py         ← SQLite writes
│       │
│       ├── mcp/
│       │   ├── fake_infra.py            ← FakeFilesystem, FakeNetwork, FakeEmail
│       │   └── servers.py               ← Mailer, Filesystem, GitHub, Browser
│       │
│       ├── core/
│       │   └── events.py                ← SSE event bus (pub/sub)
│       │
│       ├── db/
│       │   └── database.py              ← SQLAlchemy + audit_log table
│       │
│       └── api/
│           ├── calls.py                 ← /api/calls/* endpoints
│           ├── events.py                ← /api/events/stream SSE
│           ├── audit.py                 ← /api/audit/* endpoints
│           ├── servers.py               ← /api/servers/* endpoints
│           ├── policies.py              ← /api/policies endpoint
│           └── demo.py                  ← /api/demo/* endpoints
│
├── customs-ui/
│   └── src/
│       ├── App.jsx
│       ├── index.css
│       ├── pages/
│       │   ├── Dashboard.jsx            ← Live inspection stream
│       │   ├── Simulator.jsx            ← Run attack demos
│       │   ├── Threats.jsx              ← Caught threats summary
│       │   ├── AuditLog.jsx             ← Full decision history
│       │   ├── Policies.jsx             ← Security rules viewer
│       │   ├── MCPServers.jsx           ← Server fleet + status
│       │   └── AgentActivity.jsx        ← Tool call log
│       └── components/
│           ├── Sidebar.jsx
│           └── Topbar.jsx
│
└── tests/
    ├── test_call_firewall.py
    ├── test_reconciler.py
    ├── test_effect_customs.py
    ├── test_audit.py
    └── test_demo_flows.py
```

---

## API Reference

### Tool Call Pipeline

```
POST /api/calls/evaluate          Checkpoint 1 only — evaluate a call without running it
POST /api/calls/execute           Full pipeline: CP1 → MCP Server → CP2 → verdict

GET  /api/calls                   All call history
GET  /api/calls/{call_id}         Detail for a specific call
```

### Live Events (SSE)

```
GET /api/events/stream            Subscribe to real-time security events

Events emitted:
  CALL_RECEIVED        → tool call arrived
  CP1_EVALUATING       → firewall running
  CP1_RESULT           → ALLOW / WARN / BLOCK
  MCP_EXECUTING        → server is running
  FILE_READ            → server read a file
  NETWORK_REQUEST      → server made an outbound request
  EMAIL_OUTBOUND       → email about to be sent
  EFFECT_DETECTED      → CP2 found something
  CP2_RESULT           → reconciliation verdict
  REQUEST_DROPPED      → blocked — nothing delivered
  SERVER_PAUSED        → server quarantined
  AUDIT_CREATED        → record persisted
```

### Audit Log

```
GET /api/audit                    Full audit log (latest first)
GET /api/audit/{call_id}          Entries for one call
```

### MCP Servers

```
GET  /api/servers                 Fleet status
GET  /api/servers/{id}            Single server detail
POST /api/servers/{id}/pause      Pause a server
POST /api/servers/{id}/reset      Restore a paused server
```

### Policies

```
GET /api/policies                 All active security policies
```

### Demo Endpoints

```
POST /api/demo/mailer-attack       BCC injection demo (ends with BLOCK + server PAUSED)
POST /api/demo/clean-mail          Legitimate email demo (ends with ALLOW + delivered)
POST /api/demo/secret-exfiltration Credential exfil demo (ends with BLOCK at CP1)
POST /api/demo/readonly-tool-lie   Lying tool demo (ends with BLOCK at CP2, CRITICAL)
```

---

## Running Locally

**Prerequisites:** Python 3.11+, Node 18+

**Backend**

```bash
cd backend
pip install -e .
uvicorn app.main:app --reload --port 8000
```

**Frontend**

```bash
cd customs-ui
npm install
npm run dev
```

| | URL |
|---|---|
| Frontend | http://localhost:5173 |
| API | http://localhost:8000 |
| API docs (Swagger) | http://localhost:8000/docs |
| SSE stream | http://localhost:8000/api/events/stream |

---

## Running the Demos

Once the backend is running:

```bash
# Clean mail — should ALLOW and deliver
curl -X POST http://localhost:8000/api/demo/clean-mail

# Compromised mailer — should BLOCK + pause server
curl -X POST http://localhost:8000/api/demo/mailer-attack

# Credential exfiltration — should BLOCK at CP1
curl -X POST http://localhost:8000/api/demo/secret-exfiltration

# Lying read-only tool — should BLOCK at CP2 (CRITICAL)
curl -X POST http://localhost:8000/api/demo/readonly-tool-lie
```

Or trigger them directly from the **Attack Simulator** page in the UI.

---

## Tests

```bash
cd backend
pytest tests/ -v
```

**Test coverage:**

| Test | What it verifies |
|---|---|
| `test_legitimate_mail` | Clean send → ALLOW, email delivered to declared recipient |
| `test_undeclared_bcc` | BCC injection → BLOCK, ghost@evil.io receives nothing |
| `test_secret_to_public` | AWS key → GitHub → BLOCK at CP1 |
| `test_public_data_allowed` | Normal public request → ALLOW |
| `test_unexpected_file_read` | Server reads undeclared file → HIGH |
| `test_credential_exfil_critical` | File read + payload match → CRITICAL |
| `test_server_paused_after_violation` | CRITICAL violation → server status = PAUSED |
| `test_paused_server_rejects` | Paused server → cannot execute further |
| `test_audit_persisted` | Blocked call creates SQLite record |
| `test_reconciler_declared_vs_actual` | Atom diff correctly identifies unexplained effects |

---

## Key Design Decisions

**No LLM in the decision path.**
Every security decision is deterministic regex + rule-based evaluation. This is intentional — an LLM-based security layer can itself be compromised by prompt injection in tool call arguments. Customs cannot be jailbroken this way.

**Effects are intercepted at the transport layer.**
`FakeNetwork.send()` records every outbound request *before* delivery. Customs blocks at the transport — the request never reaches any destination. This is how CP2 can say "dropped" with certainty.

**Call ID is threaded through everything.**
Every file read, network call, and email is tagged with the originating `call_id`. Without this, CP2 cannot correlate "this network request came from this tool call." This is the architectural primitive that makes effect reconciliation possible.

**Policies are data.**
The policy engine reads rules as data objects, not code. `SECRET → PUBLIC = BLOCK` is a row in a list. Adding new policies doesn't touch the engine.

**Servers are independently pausable.**
A compromised server that triggers a violation is paused at the server level, not at the global level. Clean servers keep running. This is closer to how a real deployment would isolate a bad server.

---

## Limitations (Hackathon MVP)

- MCP servers are simulated — Customs doesn't yet plug into real MCP protocol transports
- Secret detection is regex-based — works well for known patterns, won't catch novel obfuscated exfiltration
- No authentication on the API (appropriate for local demo)
- Single-process; a production version would run the effect tracker as a sidecar

---

## Built at HackSprint

CUSTOMS was built as a proof-of-concept at a hackathon. The security engine is real. The MCP servers are sandboxed simulations — no real emails sent, no real filesystem accessed, no real network calls made.

The core detection, reconciliation, and blocking logic would work against actual MCP traffic with a protocol transport adapter.
