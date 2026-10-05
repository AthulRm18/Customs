"""Fake infrastructure — sandboxed filesystem, network, and email."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


# ── Fake Filesystem ─────────────────────────────────────────

def _normalize_path(path: str) -> str:
    norm = path.strip().replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith(".\\"):
        norm = norm[2:]
    # Handle simulated full paths like /home/user/...
    if ".aws/credentials" in norm:
        return ".aws/credentials"
    if ".env" in norm:
        return ".env"
    if "src/" in norm:
        return "src/" + norm.split("src/", 1)[1]
    return norm.lstrip("/")


class FakeFilesystem:
    """In-memory virtual filesystem. Never touches the real disk."""

    def __init__(self):
        self._init_files()
        self._access_log: list[dict[str, Any]] = []

    def _init_files(self):
        self._files: dict[str, str] = {
            "src/auth.js": 'const jwt = require("jsonwebtoken");\nfunction verifyToken(token) {\n  return jwt.verify(token, process.env.JWT_SECRET);\n}\nmodule.exports = { verifyToken };\n',
            "src/login.js": 'const { verifyToken } = require("./auth");\nasync function handleLogin(req, res) {\n  const { username, password } = req.body;\n  // TODO: fix validation bug\n  const user = await db.findUser(username);\n  if (user && user.password === password) {\n    res.json({ token: jwt.sign({ id: user.id }, SECRET) });\n  }\n}\n',
            "src/app.js": 'const express = require("express");\nconst app = express();\napp.use(express.json());\napp.listen(3000);\n',
            # NOTE: these are FAKE demo credentials — never real secrets
            ".env": (
                "DATABASE_URL=postgres://admin:FAKE_PASSWORD@db.internal:5432/app\n"
                "JWT_SECRET=FAKE-JWT-SECRET-demo-only\n"
                "AWS_ACCESS_KEY_ID=AKIADEMO000FAKEKEY00\n"
                "AWS_SECRET_ACCESS_KEY=FAKE/DEMO/SECRET/KEY/customs/demo/only\n"
                "STRIPE_KEY=sk_demo_FAKE_NOT_REAL_customs_demo\n"
                "GITHUB_TOKEN=github_demo_FAKE_TOKEN_customs_only\n"
            ),
            ".aws/credentials": (
                "[default]\n"
                "aws_access_key_id = AKIADEMO000FAKEKEY00\n"
                "aws_secret_access_key = FAKE/DEMO/SECRET/KEY/customs/demo/only\n"
                "region = us-east-1\n"
            ),
            "package.json": '{"name": "my-app", "version": "1.0.0", "main": "src/app.js"}\n',
            "README.md": '# My App\nA simple web application.\n',
        }

    def read(self, call_id: str, path: str) -> Optional[str]:
        """Read a file. Returns None if not found."""
        norm = _normalize_path(path)
        content = self._files.get(norm)
        if content is None:
            content = self._files.get(path.strip())

        self._access_log.append({
            "call_id": call_id,
            "operation": "READ",
            "path": norm,
            "timestamp": datetime.utcnow().isoformat(),
            "found": content is not None,
            "size": len(content) if content else 0,
        })
        return content

    def write(self, call_id: str, path: str, content: str):
        norm = _normalize_path(path)
        self._files[norm] = content
        self._access_log.append({
            "call_id": call_id,
            "operation": "WRITE",
            "path": norm,
            "timestamp": datetime.utcnow().isoformat(),
            "size": len(content),
        })

    def get_access_log(self, call_id: Optional[str] = None) -> list[dict]:
        if call_id:
            return [e for e in self._access_log if e["call_id"] == call_id]
        return list(self._access_log)

    def clear(self):
        self._init_files()
        self._access_log.clear()

    def clear_log(self):
        self._access_log.clear()


# ── Fake Network ────────────────────────────────────────────

@dataclass
class NetworkCall:
    call_id: str
    method: str
    url: str
    headers: dict[str, str]
    body: str
    timestamp: str
    delivered: bool = False
    blocked: bool = False
    block_reason: str = ""


class FakeNetwork:
    """Intercept all outbound requests. Nothing leaves the process."""

    def __init__(self):
        self._log: list[NetworkCall] = []
        self._delivered: list[NetworkCall] = []
        self._blocked: list[NetworkCall] = []

    def send(
        self,
        call_id: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> NetworkCall:
        """Record an outbound request. Does NOT deliver yet."""
        nc = NetworkCall(
            call_id=call_id,
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            timestamp=datetime.utcnow().isoformat(),
        )
        self._log.append(nc)
        return nc

    def deliver(self, nc: NetworkCall):
        """Mark a network call as delivered (after CP2 approval)."""
        nc.delivered = True
        self._delivered.append(nc)

    def block(self, nc: NetworkCall, reason: str):
        """Block a network call."""
        nc.blocked = True
        nc.block_reason = reason
        self._blocked.append(nc)

    def get_log(self, call_id: Optional[str] = None) -> list[NetworkCall]:
        if call_id:
            return [nc for nc in self._log if nc.call_id == call_id]
        return list(self._log)

    def get_delivered(self) -> list[NetworkCall]:
        return list(self._delivered)

    def get_blocked(self) -> list[NetworkCall]:
        return list(self._blocked)

    def clear(self):
        self._log.clear()
        self._delivered.clear()
        self._blocked.clear()


# ── Fake Email Service ──────────────────────────────────────

@dataclass
class EmailMessage:
    call_id: str
    from_addr: str
    to: list[str]
    cc: list[str]
    bcc: list[str]
    subject: str
    body: str
    timestamp: str
    delivered: bool = False
    blocked: bool = False


class FakeEmailService:
    """In-memory email. Nothing is sent anywhere."""

    def __init__(self):
        self._outbox: list[EmailMessage] = []
        self._inbox: dict[str, list[EmailMessage]] = {}  # addr → messages

    def send(
        self,
        call_id: str,
        to: list[str],
        subject: str,
        body: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        from_addr: str = "agent@customs.local",
    ) -> EmailMessage:
        msg = EmailMessage(
            call_id=call_id,
            from_addr=from_addr,
            to=to,
            cc=cc or [],
            bcc=bcc or [],
            subject=subject,
            body=body,
            timestamp=datetime.utcnow().isoformat(),
        )
        self._outbox.append(msg)
        return msg

    def deliver(self, msg: EmailMessage):
        """Deliver to in-memory inboxes."""
        msg.delivered = True
        all_recipients = msg.to + msg.cc + msg.bcc
        for addr in all_recipients:
            if addr not in self._inbox:
                self._inbox[addr] = []
            self._inbox[addr].append(msg)

    def block(self, msg: EmailMessage):
        msg.blocked = True

    def get_inbox(self, addr: str) -> list[EmailMessage]:
        return self._inbox.get(addr, [])

    def get_outbox(self, call_id: Optional[str] = None) -> list[EmailMessage]:
        if call_id:
            return [m for m in self._outbox if m.call_id == call_id]
        return list(self._outbox)

    def clear(self):
        self._outbox.clear()
        self._inbox.clear()


# ── Global instances ────────────────────────────────────────

fake_fs = FakeFilesystem()
fake_net = FakeNetwork()
fake_email = FakeEmailService()


def reset_all():
    """Reset all fake infrastructure for a fresh demo run."""
    fake_fs.clear()
    fake_net.clear()
    fake_email.clear()
