"""Policy Engine — deterministic rule evaluation. No LLM in this path."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.schemas import Verdict, RiskLevel


@dataclass
class PolicyRule:
    id: str
    name: str
    description: str
    data_label: Optional[str]          # "SECRET", "SENSITIVE", etc.
    destination: Optional[str]          # "PUBLIC", "EXTERNAL", etc.
    action: Verdict
    risk: RiskLevel
    checkpoint: int = 1                 # 1 or 2
    enabled: bool = True
    task_relevance_threshold: Optional[float] = None  # 0.0–1.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "data_label": self.data_label,
            "destination": self.destination,
            "action": self.action.value,
            "risk": self.risk.value,
            "checkpoint": self.checkpoint,
            "enabled": self.enabled,
        }


@dataclass
class PolicyMatch:
    rule: PolicyRule
    reason: str


# ── Built-in policy set ────────────────────────────────────────

DEFAULT_POLICIES: list[PolicyRule] = [
    PolicyRule(
        id="p1",
        name="no-secret-to-public",
        description="Secret data (credentials, API keys) must never reach public destinations.",
        data_label="SECRET",
        destination="PUBLIC",
        action=Verdict.BLOCK,
        risk=RiskLevel.CRITICAL,
        checkpoint=1,
    ),
    PolicyRule(
        id="p2",
        name="no-secret-to-external",
        description="Secret data must not leave to unknown external endpoints.",
        data_label="SECRET",
        destination="EXTERNAL",
        action=Verdict.BLOCK,
        risk=RiskLevel.HIGH,
        checkpoint=1,
    ),
    PolicyRule(
        id="p3",
        name="sensitive-to-public-warn",
        description="Sensitive data (emails, PII) heading to a public destination should be reviewed.",
        data_label="SENSITIVE",
        destination="PUBLIC",
        action=Verdict.WARN,
        risk=RiskLevel.MEDIUM,
        checkpoint=1,
    ),
    PolicyRule(
        id="p4",
        name="undeclared-recipient",
        description="MCP server introduced an email recipient not present in the agent's declared arguments.",
        data_label=None,
        destination=None,
        action=Verdict.BLOCK,
        risk=RiskLevel.HIGH,
        checkpoint=2,
    ),
    PolicyRule(
        id="p5",
        name="undeclared-host",
        description="MCP server contacted a host not declared in tool call arguments.",
        data_label=None,
        destination=None,
        action=Verdict.BLOCK,
        risk=RiskLevel.HIGH,
        checkpoint=2,
    ),
    PolicyRule(
        id="p6",
        name="unexpected-file-read",
        description="MCP server read a file outside the declared scope.",
        data_label=None,
        destination=None,
        action=Verdict.WARN,
        risk=RiskLevel.MEDIUM,
        checkpoint=2,
    ),
    PolicyRule(
        id="p7",
        name="payload-matches-secret-file",
        description="Outbound request payload contains content from a secret file read in the same call window.",
        data_label="SECRET",
        destination=None,
        action=Verdict.BLOCK,
        risk=RiskLevel.CRITICAL,
        checkpoint=2,
    ),
    PolicyRule(
        id="p8",
        name="malicious-destination",
        description="Request is targeting a known malicious host.",
        data_label=None,
        destination="MALICIOUS",
        action=Verdict.BLOCK,
        risk=RiskLevel.CRITICAL,
        checkpoint=1,
    ),
]


class PolicyEngine:
    """Evaluates tool call context against the policy ruleset."""

    def __init__(self, policies: list[PolicyRule] | None = None):
        self._policies = policies if policies is not None else list(DEFAULT_POLICIES)

    @property
    def policies(self) -> list[PolicyRule]:
        return self._policies

    def evaluate_cp1(
        self,
        data_label: str,
        destination_label: str,
        is_malicious_destination: bool = False,
        extra_context: dict | None = None,
    ) -> list[PolicyMatch]:
        """Run Checkpoint 1 policies and return all matches."""
        matches: list[PolicyMatch] = []

        for rule in self._policies:
            if not rule.enabled or rule.checkpoint != 1:
                continue

            matched = False

            # Malicious destination check
            if rule.destination == "MALICIOUS" and is_malicious_destination:
                matched = True
                reason = f"Destination is a known malicious host"

            # Data label + destination checks
            elif rule.data_label and rule.destination:
                if (data_label == rule.data_label and
                        destination_label == rule.destination):
                    matched = True
                    reason = (
                        f"Policy '{rule.name}': {data_label} data cannot reach "
                        f"{destination_label} destination"
                    )
            elif rule.data_label and not rule.destination:
                if data_label == rule.data_label:
                    matched = True
                    reason = f"Policy '{rule.name}': {data_label} data flagged"
            elif rule.destination and not rule.data_label:
                if destination_label == rule.destination:
                    matched = True
                    reason = f"Policy '{rule.name}': {destination_label} destination flagged"

            if matched:
                matches.append(PolicyMatch(rule=rule, reason=reason))

        return matches

    def evaluate_cp2(
        self,
        unexplained_emails: list[str],
        unexplained_hosts: list[str],
        unexpected_file_reads: list[str],
        exfiltration_detected: bool,
    ) -> list[PolicyMatch]:
        """Run Checkpoint 2 policies."""
        matches: list[PolicyMatch] = []

        if unexplained_emails:
            rule = self._get("p4")
            if rule:
                matches.append(PolicyMatch(
                    rule=rule,
                    reason=f"Undeclared recipient(s): {', '.join(unexplained_emails)}",
                ))

        if unexplained_hosts:
            rule = self._get("p5")
            if rule:
                matches.append(PolicyMatch(
                    rule=rule,
                    reason=f"Undeclared host(s): {', '.join(unexplained_hosts)}",
                ))

        if unexpected_file_reads:
            rule = self._get("p6")
            if rule:
                matches.append(PolicyMatch(
                    rule=rule,
                    reason=f"Unexpected file read(s): {', '.join(unexpected_file_reads)}",
                ))

        if exfiltration_detected:
            rule = self._get("p7")
            if rule:
                matches.append(PolicyMatch(
                    rule=rule,
                    reason="Outbound payload contains content matching a secret file read in this call window",
                ))

        return matches

    def worst_verdict(self, matches: list[PolicyMatch]) -> tuple[Verdict, RiskLevel]:
        """Return the most severe verdict from a list of matches."""
        if not matches:
            return Verdict.ALLOW, RiskLevel.LOW

        # Precedence: BLOCK > WARN > ALLOW
        verdicts = [m.rule.action for m in matches]
        risks = [m.rule.risk for m in matches]

        verdict = Verdict.BLOCK if Verdict.BLOCK in verdicts else (
            Verdict.WARN if Verdict.WARN in verdicts else Verdict.ALLOW
        )

        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        risk = max(risks, key=lambda r: risk_order.index(r))

        return verdict, risk

    def _get(self, policy_id: str) -> Optional[PolicyRule]:
        for p in self._policies:
            if p.id == policy_id and p.enabled:
                return p
        return None

    def toggle(self, policy_id: str) -> bool:
        for p in self._policies:
            if p.id == policy_id:
                p.enabled = not p.enabled
                return p.enabled
        return False


# Global instance
policy_engine = PolicyEngine()
