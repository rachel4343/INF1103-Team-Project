# ==============================================
# PHISHGUARD — Part 1: Collect Information
# ==============================================

import json
import os
import re
from typing import Dict

DATA_FILE = "phishguard_reports.json"

def collect_report() -> Dict:
    print("\n" + "=" * 50)
    print("       PHISHGUARD — Report Suspicious Email")
    print("=" * 50)
    print("Answer the questions below.\n")

    print(" 1. Sender")
    sender_email = input("  Sender email   : ").strip()
    sender_name  = input("  Sender name    : ").strip()

    print("\n 2. Email Content")
    subject = input("  Email subject  : ").strip()
    body    = input("  Email message  : ").strip()

    print("\n 3. Links & Attachments")
    print("  (Separate multiple with comma , )")
    links_text  = input("  Links found    : ").strip()
    attach_text = input("  Attachments    : ").strip()

    print("\n 4. Extra Info")
    suspicion = input("  Why suspicious? : ").strip()
    actions   = input("  Actions taken  : ").strip().lower()

    links = [item.strip() for item in links_text.split(",") if item.strip()]
    files = [item.strip() for item in attach_text.split(",") if item.strip()]

    errors = []
    if not body:
        errors.append("  Please type the email message — it's needed!")
    if not sender_email and not sender_name:
        errors.append("  Need at least sender email OR name")

    if errors:
        print("\n" + "-" * 50)
        for msg in errors:
            print(msg)
        print("-" * 50)
        return {}

    print("\n Information collected successfully!\n")
    return {
        "sender_email": sender_email,
        "sender_name":  sender_name,
        "subject":      subject,
        "body":         body,
        "links":        links,
        "attachments":  files,
        "suspicion":    suspicion,
        "actions":      actions
    }

# ==============================================
# PART 2: AI MANAGER — Analyze Email
# ==============================================

def analyze_email(report: Dict) -> Dict:
    print("\n" + "-" * 50)
    print(" Checking for phishing signs...")
    print("-" * 50)

    full_text = f"{report['subject']} {report['body']}".lower()
    sender_info = f"{report['sender_name']} {report['sender_email']}".lower()

    impersonation = (
        bool(re.search(r"(it|support|admin|helpdesk|security)", sender_info))
        and
        bool(re.search(r"(verify|account|login|suspend)", full_text))
    )

    urgency = bool(re.search(
        r"(urgent|immediately|now|expire|close|suspend|deadline)", full_text
    ))

    credential_request = bool(re.search(
        r"(password|otp|credential|verify|username|login|pin)", full_text
    ))

    suspicious_link = (
        len(report["links"]) > 0
        or
        bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|login|verify)", full_text))
    )

    risky_attachment = len(report["attachments"]) > 0

    total_signs = sum([
        impersonation,
        urgency,
        credential_request,
        suspicious_link,
        risky_attachment
    ])

    found = []
    if impersonation:    found.append("Impersonation")
    if urgency:          found.append("Urgency/Pressure")
    if credential_request: found.append("Asking for credentials")
    if suspicious_link:  found.append("Suspicious links")
    if risky_attachment: found.append("Risky attachments")

    if found:
        print(f"   Found: {', '.join(found)}")
    else:
        print("   No phishing signs detected")

    if total_signs >= 4:
        threat_level = "critical"
        confidence = 0.90
    elif total_signs == 3:
        threat_level = "high"
        confidence = 0.85
    elif total_signs == 2:
        threat_level = "medium"
        confidence = 0.75
    elif total_signs == 1:
        threat_level = "low"
        confidence = 0.65
    else:
        threat_level = "low"
        confidence = 0.95

    print(f"\n   Threat Level: {threat_level.upper()}")
    print(f"   Confidence:   {confidence:.0%}")

    return {
        "threat_level": threat_level,
        "confidence": confidence,
        "impersonation": impersonation,
        "urgency": urgency,
        "credential_request": credential_request,
        "suspicious_link": suspicious_link,
        "risky_attachment": risky_attachment,
        "signs_found": total_signs
    }

# ==============================================
# PART 3: LOGIC MANAGER — Apply Business Rules
# ==============================================

def decide_priority(assessment: Dict) -> Dict:
    """Use AI result to decide final priority & action"""
    print("\n" + "-" * 50)
    print("  Applying business rules...")
    print("-" * 50)

    # Get values from AI assessment
    tl   = assessment["threat_level"]
    conf = assessment["confidence"]
    imp  = assessment["impersonation"]
    urg  = assessment["urgency"]
    cred = assessment["credential_request"]
    link = assessment["suspicious_link"]

    # Set default
    priority = " MANUAL REVIEW"
    action   = "Needs staff review"

    # Apply your rules one by one
    if tl == "critical" and conf >= 0.85:
        priority = " CRITICAL"
        action   = "Immediate Security Investigation — block sender now"
    elif cred and link and conf >= 0.80:
        priority = " URGENT"
        action   = "Investigate within 1 hour — block suspicious link"
    elif imp and urg and tl == "high":
        priority = " HIGH"
        action   = "Investigate within 24 hours"
    elif tl == "medium" and conf >= 0.75:
        priority = " MEDIUM"
        action   = "Review during next business day"
    elif tl == "low" and conf >= 0.90 and not link:
        priority = " LOW"
        action   = "Likely safe — routine review"
    elif conf < 0.60:
        priority = " MANUAL REVIEW"
        action   = "System uncertain — staff check needed"

    # Extra safety: if says LOW but has red flags → upgrade
    if "LOW" in priority and (imp or cred or link):
        priority = " MEDIUM"
        action   = "Re-evaluate — mixed signals detected"

    # Show result
    print(f"   Final Priority: {priority}")
    print(f"   Recommended:    {action}")

    return {
        "priority": priority,
        "action": action,
        "ai_assessment": assessment
    }
    
# ==============================================
# PART 4: DATA MANAGER — Save & Load Reports
# ==============================================

def save_report(report: Dict, decision: Dict) -> None:
    """Save full record to JSON file, handle missing/corrupted files"""
    records = []

    # Load existing reports if file exists
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                records = json.load(f)
        except (json.JSONDecodeError, IOError):
            # If file broken, start fresh
            records = []
            print("     Previous file corrupted — starting new record")

    # Combine everything into one neat record
    full_record = {
        "report":       report,
        "decision":     decision,
        "status":       "Pending Review"
    }

    # Add to list and save
    records.append(full_record)

    with open(DATA_FILE, "w") as f:
        json.dump(records, f, indent=2)

    print(f"\n Report saved! Total reports: {len(records)}")
    print(f"   Stored in: {DATA_FILE}")


def load_reports(filter_priority=None):
    """Read all saved reports; optionally filter by priority"""
    if not os.path.exists(DATA_FILE):
        print("   No reports file found yet")
        return []

    try:
        with open(DATA_FILE, "r") as f:
            records = json.load(f)
    except:
        return []

    if filter_priority:
        return [r for r in records if r["decision"]["priority"] == filter_priority]
    return records

# ==============================================
# MAIN — FULL PROGRAM: All 4 Parts Together
# ==============================================

def main():
    print("\n" + "=" * 50)
    print("       PHISHGUARD — Phishing Detector")
    print("=" * 50)
    print("  Answer each question to submit a report.\n")

    # 1️⃣ Collect info
    report = collect_report()
    if not report:
        print(" Submission cancelled — missing required info.")
        return

    # 2️⃣ Analyze for phishing signs
    assessment = analyze_email(report)

    # 3️⃣ Decide priority
    decision = decide_priority(assessment)

    # 4️⃣ Save everything
    save_report(report, decision)

    # Done!
    print("\n" + "=" * 50)
    print(" SUBMISSION COMPLETE — Thank you!")
    print("=" * 50)

if __name__ == "__main__":
    main()