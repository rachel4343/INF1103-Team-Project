"""
Data Manager
------------
Reads/writes reports to a JSON file. Handles missing/corrupted files
safely. Supports simple filtering.
"""

import json
import os

DATA_FILE = "reports.json"


def load_reports(path=DATA_FILE):
    """Loads all reports. Returns [] if file is missing or corrupted."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                print("Warning: data file is not a list, starting fresh.")
                return []
            return data
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Warning: could not read data file ({exc}), starting fresh.")
        return []


def save_reports(reports, path=DATA_FILE):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
    except OSError as exc:
        print(f"Error: could not save reports ({exc})")


def next_id(reports):
    if not reports:
        return 1
    return max(r.get("id", 0) for r in reports) + 1


def add_report(reports, record):
    reports.append(record)
    return reports


def find_report(reports, report_id):
    for r in reports:
        if str(r.get("id")) == str(report_id):
            return r
    return None


def filter_reports(reports, threat_level=None, attack_type=None, status=None):
    """Simple filtering by one or more fields. No AI involved."""
    results = reports
    if threat_level:
        results = [
            r for r in results
            if r.get("ai_analysis") and r["ai_analysis"].get("threat_level") == threat_level
        ]
    if attack_type:
        results = [
            r for r in results
            if r.get("ai_analysis") and r["ai_analysis"].get("attack_type") == attack_type
        ]
    if status:
        results = [r for r in results if r.get("status") == status]
    return results
