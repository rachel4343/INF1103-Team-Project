"""
I/O Manager
-----------
Handles all terminal input/output: menus, prompting for report fields,
prompting for personnel actions, and basic input validation.
No AI calls happen here. No business logic happens here.
"""

VALID_ACTIONS_TAKEN = ["clicked", "opened", "entered_info", "none"]


def show_main_menu():
    print("\n=== PhishGuard ===")
    print("1. Submit a suspicious email report (Employee)")
    print("2. Review reports (IT/Cybersecurity Personnel)")
    print("3. Exit")
    return input("Choose an option: ").strip()


def collect_employee_report():
    """
    Collects a raw employee report as a plain dict.
    Returns None if required fields are missing (basic validation).
    """
    print("\n--- New Suspicious Email Report ---")
    report = {
        "sender": input("Sender's email/display name: ").strip(),
        "subject": input("Email subject: ").strip(),
        "body": input("Email body (paste text): ").strip(),
        "urls": input("URLs found (comma-separated, or leave blank): ").strip(),
        "attachment_description": input(
            "Attachment description (filename/type, or leave blank): "
        ).strip(),
        "reason_for_suspicion": input("Why do you think this is suspicious? ").strip(),
        "actions_taken": _prompt_actions_taken(),
    }

    if not report["sender"] or not report["subject"] or not report["body"]:
        print("Error: sender, subject, and body are required.")
        return None

    return report


def _prompt_actions_taken():
    print(f"Actions taken {VALID_ACTIONS_TAKEN}:")
    choice = input("Enter one: ").strip().lower()
    if choice not in VALID_ACTIONS_TAKEN:
        print("Invalid choice, defaulting to 'none'.")
        return "none"
    return choice


def show_report_list(reports):
    print("\n--- Reports ---")
    if not reports:
        print("No reports found.")
        return
    for r in reports:
        print(
            f"[{r.get('id')}] priority={r.get('final_priority')} "
            f"status={r.get('status')} subject={r.get('subject')}"
        )


def collect_personnel_update():
    """
    Collects a status update / override / notes for an existing report.
    No AI involved — plain data entry.
    """
    report_id = input("Report ID to update: ").strip()
    status = input("New status (New/In Progress/Closed, or blank to skip): ").strip()
    override = input("Priority override (or blank to skip): ").strip()
    notes = input("Investigation notes (or blank to skip): ").strip()
    reviewer = input("Assigned reviewer (or blank to skip): ").strip()
    return {
        "id": report_id,
        "status": status or None,
        "priority_override": override or None,
        "notes": notes or None,
        "assigned_reviewer": reviewer or None,
    }
