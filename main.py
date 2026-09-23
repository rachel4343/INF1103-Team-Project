"""
PhishGuard - Main entry point.
Ties together I/O Manager, AI Manager, Logic Manager, Data Manager.
Fully procedural - no classes.
"""

import io_manager
import ai_manager
import logic_manager
import data_manager


def handle_employee_submission(reports):
    report = io_manager.collect_employee_report()
    if report is None:
        return reports

    ai_data = ai_manager.analyse_report(report)
    priority, handling = logic_manager.determine_priority(ai_data)

    report_id = data_manager.next_id(reports)
    record = logic_manager.build_final_record(
        report_id, report, ai_data, priority, handling
    )
    reports = data_manager.add_report(reports, record)
    data_manager.save_reports(reports)

    print(f"\nReport submitted. ID={report_id}, Priority={priority}, Handling={handling}")
    return reports


def handle_personnel_review(reports):
    io_manager.show_report_list(reports)
    if not reports:
        return reports

    update = io_manager.collect_personnel_update()
    record = data_manager.find_report(reports, update["id"])
    if record is None:
        print("Report ID not found.")
        return reports

    logic_manager.apply_personnel_update(record, update)
    data_manager.save_reports(reports)
    print("Report updated.")
    return reports


def main():
    reports = data_manager.load_reports()

    while True:
        choice = io_manager.show_main_menu()

        if choice == "1":
            reports = handle_employee_submission(reports)
        elif choice == "2":
            reports = handle_personnel_review(reports)
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid option, try again.")


if __name__ == "__main__":
    main()
