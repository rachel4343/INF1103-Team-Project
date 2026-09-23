"""
Logic Manager
-------------
Applies deterministic business rules to the validated AI output to decide
the final priority and recommended handling. No AI calls here.
"""

MANUAL_REVIEW = "Manual Review Required"


def determine_priority(ai_data):
    """
    ai_data: validated dict from ai_manager.analyse_report(), or None if
    the AI failed validation after retry.
    Returns (priority: str, handling: str)
    """
    if ai_data is None:
        return MANUAL_REVIEW, "Manual review by IT/Cybersecurity personnel."

    threat_level = ai_data["threat_level"]
    confidence = ai_data["confidence"]
    impersonation = ai_data["impersonation"]
    urgency = ai_data["urgency_manipulation"]
    credential_request = ai_data["credential_request"]
    suspicious_link = ai_data["suspicious_link"]

    if threat_level == "critical" and confidence >= 0.85:
        return "Critical", "Immediate Security Investigation"

    if credential_request and suspicious_link and confidence >= 0.80:
        return "Urgent", "Urgent Security Review"

    if impersonation and urgency and threat_level == "high":
        return "High", "High-Priority Review"

    if threat_level == "medium" and confidence >= 0.75:
        return "Medium", "Security Review"

    if threat_level == "low" and confidence >= 0.90 and not suspicious_link:
        return "Low", "Routine Review"

    # Anything that doesn't clearly match a rule above but has usable data:
    # prioritise the higher-risk outcome rather than silently dropping it.
    if threat_level in ("critical", "high") or credential_request or suspicious_link:
        return "High", "High-Priority Review"

    return MANUAL_REVIEW, "Manual review by IT/Cybersecurity personnel."


def build_final_record(report_id, employee_report, ai_data, priority, handling):
    """Combines everything into the record that Data Manager will store."""
    return {
        "id": report_id,
        "employee_report": employee_report,
        "ai_analysis": ai_data,
        "final_priority": priority,
        "recommended_handling": handling,
        "status": "New",
        "priority_override": None,
        "notes": None,
        "assigned_reviewer": None,
    }


def apply_personnel_update(record, update):
    """
    Applies a personnel update (status/override/notes/reviewer) onto an
    existing record. If priority_override is set, it takes precedence over
    final_priority for display/reporting purposes.
    """
    if update.get("status"):
        record["status"] = update["status"]
    if update.get("priority_override"):
        record["priority_override"] = update["priority_override"]
    if update.get("notes"):
        record["notes"] = update["notes"]
    if update.get("assigned_reviewer"):
        record["assigned_reviewer"] = update["assigned_reviewer"]
    return record
