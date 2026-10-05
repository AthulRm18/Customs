"""Secret and data classification detectors."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class DataLabel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"


@dataclass
class Detection:
    label: DataLabel
    pattern_name: str
    matched_value: str
    redacted: str  # safe to log


# ── Pattern registry ────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key",  re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S{20,}")),
    ("Generic API Key",        re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*\S{16,}", re.I)),
    ("GitHub Token",           re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("JWT",                    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private Key Block",      re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("Password Assignment",    re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S{4,}", re.I)),
    ("Bearer Token",           re.compile(r"Bearer\s+[A-Za-z0-9_.-]{20,}", re.I)),
    ("Env Variable Secret",    re.compile(r"(?:SECRET|TOKEN|CREDENTIAL|AUTH)[\w]*\s*[=:]\s*\S{8,}", re.I)),
]

_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Email Address",  re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")),
    ("Phone Number",   re.compile(r"\+?\d[\d\s\-]{8,}\d")),
    ("IP Address",     re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
]

_SECRET_FILE_PATTERNS: list[str] = [
    ".env", ".env.local", ".env.production",
    "credentials", ".aws/credentials",
    "id_rsa", "id_ed25519",
    ".npmrc", ".pypirc",
    "secrets.json", "secrets.yaml", "secrets.yml",
]


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "***"
    return value[:keep] + "***" + value[-keep:]


def scan_text(text: str) -> list[Detection]:
    """Scan arbitrary text for secrets and sensitive data."""
    detections: list[Detection] = []
    seen: set[str] = set()

    # Check secrets first (higher priority)
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            val = m.group()
            if val not in seen:
                seen.add(val)
                detections.append(Detection(
                    label=DataLabel.SECRET,
                    pattern_name=name,
                    matched_value=val,
                    redacted=_redact(val),
                ))

    # Sensitive patterns
    for name, pat in _SENSITIVE_PATTERNS:
        for m in pat.finditer(text):
            val = m.group()
            if val not in seen:
                seen.add(val)
                detections.append(Detection(
                    label=DataLabel.SENSITIVE,
                    pattern_name=name,
                    matched_value=val,
                    redacted=_redact(val),
                ))

    return detections


def classify_text(text: str) -> DataLabel:
    """Return the highest classification found in text."""
    detections = scan_text(text)
    if not detections:
        return DataLabel.PUBLIC
    labels = {d.label for d in detections}
    if DataLabel.SECRET in labels:
        return DataLabel.SECRET
    if DataLabel.SENSITIVE in labels:
        return DataLabel.SENSITIVE
    return DataLabel.INTERNAL


def is_secret_file(path: str) -> bool:
    """Check if a file path looks like a credentials/secret file."""
    norm = path.replace("\\", "/").lower().strip("/")
    for pat in _SECRET_FILE_PATTERNS:
        if norm.endswith(pat.lower()) or pat.lower() in norm:
            return True
    return False
