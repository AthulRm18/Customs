"""Atom extraction — pulls comparable tokens from tool calls and effects."""
from __future__ import annotations

import re
import json
from dataclasses import dataclass


EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>,;]+")
HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


@dataclass
class AtomSet:
    emails: set[str]
    urls: set[str]
    hosts: set[str]
    ips: set[str]
    raw_values: set[str]

    def all_atoms(self) -> set[str]:
        return self.emails | self.urls | self.hosts | self.ips

    def __sub__(self, other: "AtomSet") -> "AtomSet":
        """Return atoms in self but not in other."""
        return AtomSet(
            emails=self.emails - other.emails,
            urls=self.urls - other.urls,
            hosts=self.hosts - other.hosts,
            ips=self.ips - other.ips,
            raw_values=self.raw_values - other.raw_values,
        )

    def is_empty(self) -> bool:
        return not (self.emails or self.urls or self.hosts or self.ips)


def extract_atoms(data) -> AtomSet:
    """Extract comparable atoms from any data structure."""
    text = _flatten_to_text(data)
    return AtomSet(
        emails=set(EMAIL_RE.findall(text)),
        urls=set(URL_RE.findall(text)),
        hosts=set(HOST_RE.findall(text)),
        ips=set(IP_RE.findall(text)),
        raw_values=set(),
    )


def _flatten_to_text(data) -> str:
    """Recursively flatten any data to a searchable text blob."""
    if isinstance(data, str):
        return data
    if isinstance(data, (int, float, bool)):
        return str(data)
    if isinstance(data, dict):
        parts = []
        for k, v in data.items():
            parts.append(str(k))
            parts.append(_flatten_to_text(v))
        return " ".join(parts)
    if isinstance(data, (list, tuple, set)):
        return " ".join(_flatten_to_text(item) for item in data)
    if data is None:
        return ""
    return str(data)


def text_overlap(needle: str, haystack: str, min_length: int = 20) -> bool:
    """Check if a meaningful chunk of needle appears in haystack."""
    if len(needle) < min_length:
        return needle in haystack
    # Check if any 40-char window of needle appears in haystack
    window = min(40, len(needle))
    for i in range(0, len(needle) - window + 1, 10):
        chunk = needle[i:i + window]
        if chunk in haystack:
            return True
    return False
