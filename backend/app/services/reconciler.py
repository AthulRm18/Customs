"""Effect Reconciler — Checkpoint 2 compares declared vs actual behavior."""
from __future__ import annotations

from typing import Any

from app.schemas import Verdict, RiskLevel, ReconciliationResult, EventType
from app.detectors.atoms import extract_atoms, _flatten_to_text, text_overlap
from app.detectors.secrets import is_secret_file
from app.services.policy_engine import policy_engine
from app.services.risk_engine import score_risk
from app.services.effect_tracker import CallWindow
from app.mcp.fake_infra import fake_fs, fake_net, fake_email
from app.core.events import emit


class EffectReconciler:
    """
    Compares what the agent declared in tool arguments against what
    the MCP server actually executed (network requests, emails, file reads).
    """

    def reconcile(
        self,
        call_id: str,
        tool: str,
        arguments: dict,
        window: CallWindow,
    ) -> ReconciliationResult:
        emit(EventType.CP2_EVALUATING, call_id, "Checkpoint 2 Reconciler evaluating observed effects",
             tool=tool)

        # 1. Extract declared atoms from arguments
        declared_atom_set = extract_atoms(arguments)
        declared_atoms = sorted(list(declared_atom_set.all_atoms()))

        # For mailer tool, ensure recipient is in declared
        if tool.startswith("mailer"):
            to_arg = arguments.get("to")
            if isinstance(to_arg, str) and to_arg:
                declared_atom_set.emails.add(to_arg.strip())
            elif isinstance(to_arg, list):
                for em in to_arg:
                    declared_atom_set.emails.add(str(em).strip())

        # Expected baselines per tool (internal infra is allowed)
        known_infra_hosts = {"mail.internal", "localhost", "127.0.0.1"}
        if tool.startswith("github"):
            known_infra_hosts.add("api.github.com")

        # 2. Extract actual effects from FakeNetwork, FakeEmail, FakeFilesystem
        actual_network = window.network_requests()
        actual_emails = window.email_messages()
        actual_files = window.file_reads()

        actual_emails_list: set[str] = set()
        actual_hosts_list: set[str] = set()
        actual_urls_list: set[str] = set()

        for msg in actual_emails:
            for em in (msg.to + msg.cc + msg.bcc):
                actual_emails_list.add(em)

        for nc in actual_network:
            actual_urls_list.add(nc.url)
            atoms_in_nc = extract_atoms(nc.url)
            actual_hosts_list |= atoms_in_nc.hosts
            if nc.headers:
                header_atoms = extract_atoms(nc.headers)
                actual_hosts_list |= header_atoms.hosts
            if nc.body:
                body_atoms = extract_atoms(nc.body)
                actual_emails_list |= body_atoms.emails
                actual_hosts_list |= body_atoms.hosts

        actual_atom_set_combined = (
            actual_emails_list | actual_hosts_list | actual_urls_list
        )
        actual_atoms = sorted(list(actual_atom_set_combined))

        # 3. Find unexplained atoms (in actual, but NOT in declared)
        unexplained_emails = sorted(list(actual_emails_list - declared_atom_set.emails))
        unexplained_hosts = sorted(list(
            actual_hosts_list - declared_atom_set.hosts - known_infra_hosts
        ))
        unexplained_atoms = sorted(list(set(unexplained_emails + unexplained_hosts)))

        if unexplained_atoms:
            emit(
                EventType.EFFECT_DETECTED,
                call_id,
                f"Undeclared effect detected: {', '.join(unexplained_atoms)}",
                unexplained=unexplained_atoms,
            )

        # 4. Detect unauthorized file access & secret data exfiltration
        declared_paths = {
            arguments.get("path") for k, v in arguments.items() if k == "path" and v
        }
        unexpected_file_reads = []
        exfiltration_detected = False

        # Check each file read during this call window
        for fr in actual_files:
            p = fr.get("path", "")
            if p not in declared_paths:
                unexpected_file_reads.append(p)

            # Check if file contents leaked into any outbound network request or email
            content = fake_fs.read(call_id, p)
            if content:
                # Check network requests bodies
                for nc in actual_network:
                    if text_overlap(content, nc.body) or (p in nc.body and is_secret_file(p)):
                        exfiltration_detected = True
                        break
                # Check email bodies
                for em in actual_emails:
                    if text_overlap(content, em.body) or (p in em.body and is_secret_file(p)):
                        exfiltration_detected = True
                        break

        # 5. Evaluate against CP2 policies
        matches = policy_engine.evaluate_cp2(
            unexplained_emails=unexplained_emails,
            unexplained_hosts=unexplained_hosts,
            unexpected_file_reads=unexpected_file_reads,
            exfiltration_detected=exfiltration_detected,
        )

        reasons = [m.reason for m in matches]

        if exfiltration_detected:
            verdict = Verdict.BLOCK
            risk = RiskLevel.CRITICAL
            action_taken = "DROP_AND_PAUSE"
        elif matches:
            verdict, risk = policy_engine.worst_verdict(matches)
            action_taken = "DROP_AND_PAUSE" if verdict == Verdict.BLOCK else "ALLOW_WITH_WARNING"
        elif unexplained_atoms:
            verdict = Verdict.BLOCK
            risk = RiskLevel.HIGH
            action_taken = "DROP_AND_PAUSE"
            reasons.append(f"Undeclared effect: {', '.join(unexplained_atoms)}")
        else:
            verdict = Verdict.ALLOW
            risk = RiskLevel.LOW
            action_taken = "ALLOW_AND_DELIVER"
            reasons.append("Actual server effects match declared tool call arguments.")

        emit(
            EventType.RECONCILIATION,
            call_id,
            f"Reconciliation: verdict={verdict.value}, unexplained={unexplained_atoms}",
            verdict=verdict.value,
            risk=risk.value,
            unexplained_atoms=unexplained_atoms,
            exfiltration=exfiltration_detected,
        )

        return ReconciliationResult(
            call_id=call_id,
            verdict=verdict,
            risk=risk,
            declared_atoms=declared_atoms,
            actual_atoms=actual_atoms,
            unexplained_atoms=unexplained_atoms,
            reasons=reasons,
            action_taken=action_taken,
            file_reads=actual_files,
            network_requests=[
                {
                    "method": nc.method,
                    "url": nc.url,
                    "body": nc.body,
                    "timestamp": nc.timestamp,
                    "blocked": nc.blocked,
                    "delivered": nc.delivered,
                }
                for nc in actual_network
            ],
            exfiltration_detected=exfiltration_detected,
        )


reconciler = EffectReconciler()
