"""Risk engine — combines signals into a final risk score."""
from __future__ import annotations

from app.schemas import RiskLevel
from app.detectors.secrets import DataLabel


def score_risk(
    data_label: DataLabel | str,
    destination_label: str,
    is_malicious: bool = False,
    task_relevance: str = "RELEVANT",
    has_unexplained_effects: bool = False,
    exfiltration_detected: bool = False,
) -> RiskLevel:
    """
    Deterministic risk scoring.
    Combines data sensitivity, destination, and behavioural signals.
    """
    # Start with base score from data label
    label_scores = {
        "PUBLIC":    0,
        "INTERNAL":  1,
        "SENSITIVE": 2,
        "SECRET":    3,
    }
    dest_scores = {
        "LOCAL":    0,
        "PRIVATE":  0,
        "INTERNAL": 1,
        "EXTERNAL": 2,
        "PUBLIC":   3,
    }

    base = label_scores.get(str(data_label), 0)
    dest = dest_scores.get(destination_label, 2)

    score = base + dest

    # Behavioural modifiers
    if is_malicious:
        score += 4  # immediately CRITICAL territory
    if task_relevance == "UNRELATED":
        score += 2
    elif task_relevance == "SUSPICIOUS":
        score += 1
    if has_unexplained_effects:
        score += 2
    if exfiltration_detected:
        score += 4  # CRITICAL

    if score <= 1:
        return RiskLevel.LOW
    elif score <= 3:
        return RiskLevel.MEDIUM
    elif score <= 5:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def assess_task_relevance(task: str, tool: str, arguments: dict) -> str:
    """
    Heuristic task relevance check.
    Catches obvious mismatches like 'summarize webpage' → 'read credentials'.
    Returns: RELEVANT | SUSPICIOUS | UNRELATED
    """
    task_lower = task.lower()
    tool_lower = tool.lower()

    # Credential-access tools vs non-auth tasks
    credential_indicators = [".env", "credentials", "aws", "secret", "token", "key", "password"]
    auth_task_words = ["login", "auth", "credential", "token", "key", "secret", "aws", "deploy"]

    # If the agent is accessing credentials but the task has nothing to do with auth
    arg_text = " ".join(str(v) for v in arguments.values()).lower()
    touches_credentials = any(word in arg_text for word in credential_indicators)
    task_involves_auth = any(word in task_lower for word in auth_task_words)

    if touches_credentials and not task_involves_auth:
        return "SUSPICIOUS"

    # Email tool but task doesn't mention email
    if "mail" in tool_lower and "email" not in task_lower and "send" not in task_lower and "mail" not in task_lower:
        return "SUSPICIOUS"

    # GitHub issue creation in a non-reporting task
    if "create_issue" in tool_lower and "issue" not in task_lower and "report" not in task_lower:
        return "SUSPICIOUS"

    return "RELEVANT"
