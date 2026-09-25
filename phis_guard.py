# ==============================================
#  PHISHGUARD — AI-Powered Phishing Detector
#  INF1103 Team Project
#  Features: Yes/No Flow · Privacy Blur · Custom API · Keyword Tool
# ==============================================

import json
import os
import re
from typing import Dict, List

# ──────────────────────────────────────────────
#  OUR PHISHGUARD API — Unique Word Database
#  Add/remove words here anytime
# ──────────────────────────────────────────────
PHISHGUARD_API = {
    "urgency": [
        "urgent", "immediately", "now", "expire", "deadline", "suspend",
        "block", "close", "act fast", "right now", "limited time"
    ],
    "credential": [
        "password", "login", "verify", "account", "otp", "pin",
        "username", "sign in", "confirm", "credential"
    ],
    "impersonation": [
        "it support", "helpdesk", "security team", "hr department",
        "admin", "system admin", "technical team", "it department"
    ],
    "risky_links": [
        "bit.ly", "tinyurl", "goo.gl", "login-verify", "account-verify"
    ]
}

DATA_FILE = "phishguard_reports.json"

# ──────────────────────────────────────────────
#  PRIVACY PROTECTION — Blur Before Saving
# ──────────────────────────────────────────────
def blur_privacy(text: str) -> str:
    """Hide NRIC, phone, email — never save as plain text"""
    if not text:
        return text

    # NRIC: S1234567A → S*******A
    text = re.sub(r'\b([A-Za-z])\d{7}([A-Za-z])\b', r'\1*******\2', text)
    
    # Phone: 91234567 → 91****67
    text = re.sub(r'(\d{2})\d{4}(\d{2})', r'\1****\2', text)
    
    # Email: john@domain.com → j***@domain.com
    text = re.sub(r'(\w)\w+@(\w+\.\w+)', r'\1***@\2', text)
    
    return text

# ──────────────────────────────────────────────
#  API SCANNER — Our Own Detection Engine
# ──────────────────────────────────────────────
def scan_with_api(text: str, sender: str = "") -> Dict:
    """Check text against our word list → return findings + threat level"""
    t = text.lower()
    s = sender.lower()

    found = {
        "urgency": [],
        "credential": [],
        "impersonation": [],
        "risky_links": [],
        "score": 0
    }

    for word in PHISHGUARD_API["urgency"]:
        if word in t:
            found["urgency"].append(word)
            found["score"] += 1

    for word in PHISHGUARD_API["credential"]:
        if word in t:
            found["credential"].append(word)
            found["score"] += 2

    for word in PHISHGUARD_API["impersonation"]:
        if word in s and found["credential"]:
            found["impersonation"].append(word)
            found["score"] += 2

    for link in PHISHGUARD_API["risky_links"]:
        if link in t:
            found["risky_links"].append(link)
            found["score"] += 2

    # Threat level from score
    score = found["score"]
    if score >= 6:
        level, conf = "critical", 0.92
    elif score >= 4:
        level, conf = "high", 0.85
    elif score >= 2:
        level, conf = "medium", 0.72
    elif score >= 1:
        level, conf = "low", 0.60
    else:
        level, conf = "safe", 0.95

    return {
        "found": found,
        "threat_level": level,
        "confidence": conf
    }

# ──────────────────────────────────────────────
#  KEYWORD TOOL — Check Anytime, No Save
# ──────────────────────────────────────────────
def keyword_tool():
    """Scan text without submitting — safe & quick"""
    print("\n" + "-" * 50)
    print(" PHISHGUARD Keyword Checker")
    print("-" * 50)
    text = input("Paste text to scan: ")
    if not text.strip():
        print("Nothing entered.")
        return

    result = scan_with_api(text)
    f = result["found"]

    print("\n Results:")
    if f["urgency"]: print("    Urgency words:", ", ".join(f["urgency"]))
    if f["credential"]: print("    Login/Password words:", ", ".join(f["credential"]))
    if f["impersonation"]: print("    Impersonation:", ", ".join(f["impersonation"]))
    if f["risky_links"]: print("    Risky links:", ", ".join(f["risky_links"]))
    
    if result["threat_level"] == "safe":
        print("    No red flags found")
    else:
        print(f"    Threat Level: {result['threat_level'].upper()}")
    
    input("\nPress Enter to continue...")

# ──────────────────────────────────────────────
#  COLLECT — Yes/No Flow
# ──────────────────────────────────────────────
def collect_report() -> Dict:
    print("\n" + "=" * 50)
    print("        Submit Email Report")
    print("=" * 50)

    # Step 1: Did they view?
    viewed = input("\nDid you open/view this email? (yes/no): ").strip().lower()

    if viewed == "no":
        # --- NOT VIEWED — still scan & save ---
        print("\n Why didn't you view it?")
        reason = input("Type reason or description: ").strip()
        
        sender = input("Sender name/email (if known): ").strip() or "Not provided"
        subject = input("Subject line (if known): ").strip() or "Not provided"

        # Blur before anything
        sender_safe = blur_privacy(sender)
        subject_safe = blur_privacy(subject)
        reason_safe = blur_privacy(reason)
        brief_text = f"NOT VIEWED — Reason: {reason_safe} | Sender: {sender_safe} | Subject: {subject_safe}"

        # Still run our API
        assessment = scan_with_api(brief_text, sender_safe)

        return {
            "viewed": False,
            "reason_not_viewed": reason_safe,
            "sender": sender_safe,
            "subject": subject_safe,
            "note": brief_text,
            "assessment": assessment
        }

    # --- VIEWED — full details ---
    print("\n Enter Email Details")
    sender = input("Sender email   : ").strip()
    s_name = input("Sender name    : ").strip()
    subject = input("Email subject  : ").strip()
    body = input("Email message  : ").strip()

    # Blur ALL sensitive data
    sender_safe = blur_privacy(sender)
    sname_safe = blur_privacy(s_name)
    subj_safe = blur_privacy(subject)
    body_safe = blur_privacy(body)

    if body_safe != body:
        print("    Privacy protected — sensitive data hidden")

    links_in = input("Links found (comma-separated): ").strip()
    attach_in = input("Attachments: ").strip()
    actions = input("Actions taken (clicked/opened/none): ").strip().lower()

    links = [x.strip() for x in links_in.split(",") if x.strip()]
    files = [x.strip() for x in attach_in.split(",") if x.strip()]

    # Run our API
    full_text = f"{subj_safe} {body_safe}"
    sender_full = f"{sname_safe} {sender_safe}"
    assessment = scan_with_api(full_text, sender_full)

    return {
        "viewed": True,
        "sender_email": sender_safe,
        "sender_name": sname_safe,
        "subject": subj_safe,
        "body": body_safe,
        "links": links,
        "attachments": files,
        "actions": actions,
        "assessment": assessment
    }

# ──────────────────────────────────────────────
#  DECIDE — Show Result
# ──────────────────────────────────────────────
def decide_and_show(report: Dict) -> Dict:
    print("\n" + "-" * 50)
    print(" PHISHGUARD ASSESSMENT")
    print("-" * 50)

    a = report["assessment"]
    f = a["found"]

    # Show what we found
    if f["urgency"]: print("    Urgency words:", ", ".join(f["urgency"]))
    if f["credential"]: print("    Credential requests:", ", ".join(f["credential"]))
    if f["impersonation"]: print("    Impersonation:", ", ".join(f["impersonation"]))
    if f["risky_links"]: print("    Risky links:", ", ".join(f["risky_links"]))

    # Priority & action
    tl = a["threat_level"]
    if not report["viewed"]:
        priority = " REVIEW RECOMMENDED"
        action = "Do NOT open — report to IT"
    elif tl == "critical":
        priority = " CRITICAL — DO NOT CLICK"
        action = "Block sender + change passwords immediately"
    elif tl == "high":
        priority = " HIGH RISK"
        action = "Report to IT — do not reply"
    elif tl == "medium":
        priority = " SUSPICIOUS"
        action = "Verify sender through official channel"
    elif tl == "low":
        priority = " CAUTION"
        action = "Proceed with care"
    else:
        priority = " APPEARS SAFE"
        action = "No red flags detected — stay vigilant"

    print(f"\n   Priority: {priority}")
    print(f"   Action:   {action}")

    return {
        "priority": priority,
        "action": action,
        "assessment": a
    }

# ──────────────────────────────────────────────
#  SAVE — Both YES & NO go to SAME File
# ──────────────────────────────────────────────
def save_report(report: Dict, decision: Dict):
    records = []
    
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                records = json.load(f)
        except:
            records = []

    full_record = {
        "viewed_email": report["viewed"],
        "report": report,
        "decision": decision,
        "status": "Pending Review"
    }

    records.append(full_record)

    with open(DATA_FILE, "w") as f:
        json.dump(records, f, indent=2)

    print(f"\n Saved! Total reports: {len(records)}")
    print(f"   File: {DATA_FILE}")

# ──────────────────────────────────────────────
#  MAIN MENU — Start Here
# ──────────────────────────────────────────────
def main():
    while True:
        print("\n" + "=" * 50)
        print("   PHISHGUARD — Main Menu")
        print("=" * 50)
        print("  1. Submit Email Report")
        print("  2. Keyword Checker Tool")
        print("  3. Exit")
        print("=" * 50)

        choice = input("\nChoose (1-3): ").strip()

        if choice == "2":
            keyword_tool()
        elif choice == "1":
            report = collect_report()
            decision = decide_and_show(report)
            save_report(report, decision)
            print("\n Report complete!")
        elif choice == "3":
            print("\nStay Safe! ")
            break
        else:
            print(" Please choose 1, 2, or 3")

if __name__ == "__main__":
    main()