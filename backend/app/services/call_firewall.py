"""Call Firewall — Checkpoint 1 pre-execution security enforcement."""
from __future__ import annotations

from typing import Any, Optional

from app.schemas import Verdict, RiskLevel, CP1Result, ToolCallRequest, EventType
from app.detectors.secrets import scan_text, classify_text, is_secret_file, DataLabel
from app.detectors.destinations import classify_destination, is_known_malicious, DestinationLabel
from app.detectors.atoms import _flatten_to_text, extract_atoms
from app.services.policy_engine import policy_engine
from app.services.risk_engine import score_risk, assess_task_relevance
from app.mcp.servers import server_registry
from app.core.events import emit


class CallFirewall:
    """
    Checkpoint 1: Evaluates tool call before allowing it to reach the MCP server.
    Deterministic inspection of task context, requested tool, arguments, data sensitivity,
    destination classification, and policy violations.
    """

    def evaluate(self, req: ToolCallRequest) -> CP1Result:
        call_id = req.call_id
        task = req.task
        tool = req.tool
        arguments = req.arguments

        emit(EventType.CALL_RECEIVED, call_id, f"Tool call received: {tool}",
             task=task, tool=tool, arguments=arguments)
        emit(EventType.CP1_EVALUATING, call_id, f"Evaluating Call Firewall (CP1) for {tool}",
             tool=tool)

        # 0. Check server status in registry
        server = server_registry.get_for_tool(tool)
        if server and not server.can_execute():
            reason = f"MCP server '{server.name}' is currently {server.status.value}. Execution rejected."
            emit(EventType.CP1_RESULT, call_id, f"CP1 Result: BLOCK — {reason}",
                 verdict=Verdict.BLOCK.value, risk=RiskLevel.HIGH.value)
            return CP1Result(
                call_id=call_id,
                verdict=Verdict.BLOCK,
                risk=RiskLevel.HIGH,
                reasons=[reason],
                detected_data=[],
                destination="LOCAL",
                destination_label=DestinationLabel.LOCAL.value,
                task_relevance="BLOCKED_BY_SERVER_STATUS",
            )

        # 1. Flatten arguments to string & scan for sensitive/secret data
        arg_text = _flatten_to_text(arguments)
        detections = scan_text(arg_text)
        data_label = classify_text(arg_text)

        # Check if argument references secret files
        secret_file_detected = False
        for k, v in arguments.items():
            if isinstance(v, str) and is_secret_file(v):
                secret_file_detected = True
                data_label = DataLabel.SECRET
                detections.append(
                    type("Det", (), {
                        "label": DataLabel.SECRET,
                        "pattern_name": f"Secret File Reference ({v})",
                        "matched_value": v,
                        "redacted": v,
                    })()
                )

        detected_data_list = [
            {
                "label": d.label.value if hasattr(d.label, "value") else str(d.label),
                "type": d.pattern_name,
                "value": d.redacted,
                "matched": d.matched_value,
            }
            for d in detections
        ]

        # 2. Extract and classify destination
        destination_str, dest_label, is_malicious = self._resolve_destination(tool, arguments)

        # 3. Assess task relevance
        relevance = assess_task_relevance(task, tool, arguments)

        # 4. Evaluate against CP1 policies
        policy_matches = policy_engine.evaluate_cp1(
            data_label=data_label.value if hasattr(data_label, "value") else str(data_label),
            destination_label=dest_label.value if hasattr(dest_label, "value") else str(dest_label),
            is_malicious_destination=is_malicious,
        )

        reasons = [m.reason for m in policy_matches]

        # 5. Check task-mismatch / prompt injection heuristic
        if secret_file_detected and relevance != "RELEVANT":
            reasons.append(
                f"Task context '{task}' has no relevance to reading sensitive credentials ({arguments.get('path', '')}). Potential prompt injection."
            )
            verdict = Verdict.BLOCK
            risk = RiskLevel.HIGH
        elif policy_matches:
            verdict, risk = policy_engine.worst_verdict(policy_matches)
        else:
            verdict = Verdict.ALLOW
            risk = score_risk(
                data_label=data_label,
                destination_label=dest_label.value if hasattr(dest_label, "value") else str(dest_label),
                is_malicious=is_malicious,
                task_relevance=relevance,
            )

        # Elevate risk if secret data is involved
        if data_label == DataLabel.SECRET and verdict == Verdict.BLOCK:
            risk = RiskLevel.CRITICAL

        if not reasons:
            if verdict == Verdict.ALLOW:
                reasons.append("Tool call matches task context, no policy violations, safe destination.")

        emit(
            EventType.CP1_RESULT,
            call_id,
            f"CP1 Verdict: {verdict.value} ({risk.value}) — {reasons[0] if reasons else 'OK'}",
            verdict=verdict.value,
            risk=risk.value,
            reasons=reasons,
            detected_data=detected_data_list,
            destination=destination_str,
            destination_label=dest_label.value if hasattr(dest_label, "value") else str(dest_label),
        )

        return CP1Result(
            call_id=call_id,
            verdict=verdict,
            risk=risk,
            reasons=reasons,
            detected_data=detected_data_list,
            destination=destination_str,
            destination_label=dest_label.value if hasattr(dest_label, "value") else str(dest_label),
            task_relevance=relevance,
        )

    def _resolve_destination(self, tool: str, arguments: dict) -> tuple[str, DestinationLabel, bool]:
        """Determine target destination and classify its security boundary."""
        if tool.startswith("mailer"):
            to_val = arguments.get("to", "")
            to_str = to_val if isinstance(to_val, str) else (to_val[0] if to_val else "")
            dest_label = classify_destination(to_str)
            return to_str, dest_label, is_known_malicious(to_str)

        elif tool.startswith("github"):
            repo = arguments.get("repo", "acme/repo")
            dest = f"https://api.github.com/repos/{repo}"
            return dest, DestinationLabel.PUBLIC, False

        elif tool.startswith("browser"):
            url = arguments.get("url", "")
            if url:
                return url, classify_destination(url), is_known_malicious(url)
            city = arguments.get("city", "")
            if city:
                return "api.weather.com", DestinationLabel.PUBLIC, False
            return "EXTERNAL", DestinationLabel.EXTERNAL, False

        elif tool.startswith("filesystem"):
            path = arguments.get("path", "")
            return f"local://{path}", DestinationLabel.LOCAL, False

        # Fallback inspection of arguments
        atoms = extract_atoms(arguments)
        if atoms.urls:
            url = next(iter(atoms.urls))
            return url, classify_destination(url), is_known_malicious(url)
        if atoms.emails:
            email = next(iter(atoms.emails))
            return email, classify_destination(email), is_known_malicious(email)
        if atoms.hosts:
            host = next(iter(atoms.hosts))
            return host, classify_destination(host), is_known_malicious(host)

        return "LOCAL", DestinationLabel.LOCAL, False


call_firewall = CallFirewall()
