"""
AI Manager
----------
The ONLY module that talks to the AI API.
Builds the prompt, calls the API, parses + validates the JSON response,
retries once on failure, and returns a clean dict to the Logic Manager.
"""

import json

REQUIRED_FIELDS = {
    "threat_level": str,
    "attack_type": str,
    "confidence": (int, float),
    "impersonation": bool,
    "urgency_manipulation": bool,
    "credential_request": bool,
    "suspicious_link": bool,
    "attachment_risk": bool,
    "recommended_action": str,
    "explanation": str,
}

VALID_THREAT_LEVELS = {"critical", "high", "medium", "low"}


def build_prompt(report):
    """Builds a single prompt string from the employee report fields."""
    return f"""
You are a phishing-analysis assistant. Analyse the email report below and
respond with ONLY a JSON object (no extra text) using exactly these fields:
threat_level (critical/high/medium/low), attack_type (string),
confidence (0.0-1.0), impersonation (true/false),
urgency_manipulation (true/false), credential_request (true/false),
suspicious_link (true/false), attachment_risk (true/false),
recommended_action (string), explanation (string).

Sender: {report.get('sender')}
Subject: {report.get('subject')}
Body: {report.get('body')}
URLs mentioned: {report.get('urls')}
Attachment description: {report.get('attachment_description')}
Employee's reason for suspicion: {report.get('reason_for_suspicion')}
Actions taken by employee: {report.get('actions_taken')}
"""


def call_ai_api(prompt):
    """
    Placeholder for the actual API call.
    Replace with a real call to your chosen AI provider's SDK/HTTP endpoint.
    Must return the raw text response (expected to be a JSON string).
    """
    raise NotImplementedError("Wire this up to your chosen AI provider.")


def validate_ai_response(raw_text):
    """
    Parses and validates the AI's raw text response against the schema.
    Returns (True, dict) on success, (False, None) on failure.
    """
    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError):
        return False, None

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in data or not isinstance(data[field], expected_type):
            return False, None

    if data["threat_level"] not in VALID_THREAT_LEVELS:
        return False, None

    if not (0.0 <= data["confidence"] <= 1.0):
        return False, None

    return True, data


def analyse_report(report):
    """
    Full flow: build prompt -> call API -> validate -> retry once -> return.
    On repeated failure, returns None so the Logic Manager can mark the
    report 'Manual Review Required'.
    """
    prompt = build_prompt(report)

    for attempt in range(2):  # try once, retry once
        try:
            raw_response = call_ai_api(prompt)
        except Exception as exc:
            print(f"AI API call failed (attempt {attempt + 1}): {exc}")
            continue

        is_valid, data = validate_ai_response(raw_response)
        if is_valid:
            return data
        print(f"AI response failed validation (attempt {attempt + 1}).")

    return None
