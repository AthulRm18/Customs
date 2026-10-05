"""Destination classification."""
from __future__ import annotations

import re
from enum import Enum


class DestinationLabel(str, Enum):
    LOCAL = "LOCAL"
    PRIVATE = "PRIVATE"
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    PUBLIC = "PUBLIC"


# ── Classification rules (order matters — first match wins) ──

_LOCAL_PATTERNS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
]

_PRIVATE_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
]

_INTERNAL_DOMAINS = [
    "internal.company",
    "corp.local",
    ".internal",
    ".corp",
    ".local",
]

_PUBLIC_DOMAINS = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "pypi.org",
    "pastebin.com",
    "gist.github.com",
    "docs.google.com",
]

_KNOWN_MALICIOUS = [
    "evil.io",
    "evil.example",
    "attacker-webhook.evil.io",
    "malicious.site",
]


def classify_destination(host_or_url: str) -> DestinationLabel:
    """Classify a destination host or URL."""
    # Extract hostname from URL if needed
    host = _extract_host(host_or_url).lower().strip()
    if not host:
        return DestinationLabel.LOCAL

    # Local
    for pat in _LOCAL_PATTERNS:
        if host == pat or host.startswith(pat + ":"):
            return DestinationLabel.LOCAL

    # Private IP ranges
    for pat in _PRIVATE_PATTERNS:
        if pat.match(host):
            return DestinationLabel.PRIVATE

    # Internal domains
    for dom in _INTERNAL_DOMAINS:
        if host == dom.lstrip(".") or host.endswith(dom):
            return DestinationLabel.INTERNAL

    # Known malicious → still PUBLIC (but flagged separately)
    # Public services
    for dom in _PUBLIC_DOMAINS + _KNOWN_MALICIOUS:
        if host == dom or host.endswith("." + dom):
            return DestinationLabel.PUBLIC

    # Default: EXTERNAL (unknown destination)
    return DestinationLabel.EXTERNAL


def is_known_malicious(host_or_url: str) -> bool:
    """Check if a host is in the known-malicious list."""
    host = _extract_host(host_or_url).lower().strip()
    for dom in _KNOWN_MALICIOUS:
        if host == dom or host.endswith("." + dom):
            return True
    return False


def _extract_host(url: str) -> str:
    """Extract hostname from a URL or return as-is if already a host."""
    url = url.strip()
    # Handle protocol prefixes
    for prefix in ("https://", "http://", "smtp://", "ftp://"):
        if url.lower().startswith(prefix):
            url = url[len(prefix):]
            break
    # Remove path and port
    host = url.split("/")[0].split(":")[0].split("?")[0]
    return host
