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
# MAIN
# ==============================================

def main():
    print("\n===== PART 1 + PART 2 TEST =====")
    
    report = collect_report()
    if not report:
        print(" No data submitted.")
        return
    
    assessment = analyze_email(report)
    print("\n Both Part 1 & Part 2 work!")

if __name__ == "__main__":
    main()