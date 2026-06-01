# automation/workflows/normalizer.py
# Reads any Autopsy autopsy.db and normalizes all artifacts
# into our unified JSON schema.
# Completely general — works with any Autopsy case database.

import os
import sys
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from collections import defaultdict

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
from config import NORMALIZED_DIR


# ── Timestamp conversion ──────────────────────────────────────

def epoch_to_utc(epoch_seconds) -> str:
    try:
        if not epoch_seconds or int(epoch_seconds) <= 0:
            return "N/A"
        dt = datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "N/A"


# ── Artifact type mapping ─────────────────────────────────────

ARTIFACT_TYPE_MAP = {
    "Web History":                  "web_history",
    "Web Search":                   "web_search",
    "Web Cookies":                  "web_cookie",
    "Web Categories":               "web_category",
    "Recent Documents":             "recent_document",
    "Shell Bags":                   "shell_bag",
    "USB Device Attached":          "usb_device",
    "Installed Programs":           "installed_program",
    "Run Programs":                 "run_program",
    "E-Mail Messages":              "email_message",
    "Accounts":                     "account",
    "Recycle Bin":                  "recycle_bin",
    "Extension Mismatch Detected":  "extension_mismatch",
    "Encryption Detected":          "encryption_detected",
    "EXIF Metadata":                "exif_metadata",
    "User Content Suspected":       "user_content",
    "Remote Drive":                 "remote_drive",
    "Operating System Information": "os_info",
    "Data Source Usage":            "data_source_usage",
    "Associated Object":            "associated_object",
}

TIMESTAMP_FIELDS = {
    "Date Accessed", "Date Created", "Date Modified",
    "Date Sent", "Date Received", "Last Printed",
    "Date", "Date/Time"
}


def _get_primary_timestamp(attributes: dict) -> str:
    priority = [
        "Date Accessed", "Date Created", "Date Modified",
        "Date Sent", "Date Received", "Date/Time", "Date"
    ]
    for field in priority:
        if field in attributes:
            val = attributes[field]
            if val and val != "N/A":
                return val
    return "N/A"


def _build_description(artifact_type: str,
                        attributes: dict) -> str:
    if artifact_type == "web_history":
        domain = attributes.get("Domain", "")
        url    = attributes.get("URL", "unknown URL")
        return f"Visited {domain or url}"
    elif artifact_type == "web_search":
        query = attributes.get("Text",
                attributes.get("URL", "unknown"))
        return f"Searched for: {query}"
    elif artifact_type == "usb_device":
        device = attributes.get("Device ID",
                 attributes.get("Display Name", "unknown device"))
        return f"USB device connected: {device}"
    elif artifact_type == "recent_document":
        path = attributes.get("Path", "unknown file")
        return f"Recently opened: {path}"
    elif artifact_type == "run_program":
        prog = attributes.get("Program Name",
               attributes.get("Path", "unknown program"))
        return f"Program executed: {prog}"
    elif artifact_type == "installed_program":
        name = attributes.get("Program Name", "unknown program")
        return f"Program installed: {name}"
    elif artifact_type == "email_message":
        subject = attributes.get("Subject", "no subject")
        sender  = attributes.get("Sender", "unknown sender")
        return f"Email: '{subject}' from {sender}"
    elif artifact_type == "recycle_bin":
        path = attributes.get("Path", "unknown file")
        return f"Deleted file: {path}"
    elif artifact_type == "shell_bag":
        path = attributes.get("Folder Path",
               attributes.get("Value Name", "unknown folder"))
        return f"Folder accessed: {path}"
    elif artifact_type == "encryption_detected":
        path = attributes.get("Name", "unknown file")
        return f"Encryption detected: {path}"
    else:
        for val in attributes.values():
            if isinstance(val, str) and val and val != "N/A":
                return val[:100]
        return artifact_type.replace("_", " ").title()


def load_all_artifacts(db_path: str) -> list:
    """
    Load and normalize all artifacts from any autopsy.db.

    Args:
        db_path: path to any Autopsy case database

    Returns:
        list of normalized artifact dicts
    """
    conn = sqlite3.connect(db_path)

    artifacts_raw = conn.execute("""
        SELECT
            ba.artifact_id,
            bat.display_name  AS artifact_type_name,
            tf.parent_path    AS file_parent_path,
            tf.name           AS file_name,
            tf.size           AS file_size
        FROM blackboard_artifacts ba
        JOIN blackboard_artifact_types bat
            ON ba.artifact_type_id = bat.artifact_type_id
        LEFT JOIN tsk_files tf
            ON ba.obj_id = tf.obj_id
        ORDER BY ba.artifact_id
    """).fetchall()

    attributes_raw = conn.execute("""
        SELECT
            battr.artifact_id,
            batt.display_name AS attr_name,
            battr.value_text,
            battr.value_int32,
            battr.value_int64,
            battr.value_double
        FROM blackboard_attributes battr
        JOIN blackboard_attribute_types batt
            ON battr.attribute_type_id = batt.attribute_type_id
    """).fetchall()

    conn.close()

    # Group attributes by artifact_id
    attr_map = defaultdict(dict)
    for (artifact_id, attr_name,
         v_text, v_int32, v_int64, v_double) in attributes_raw:

        raw_value = v_text or v_int32 or v_int64 or v_double

        if attr_name in TIMESTAMP_FIELDS and (v_int32 or v_int64):
            epoch = v_int64 or v_int32
            attr_map[artifact_id][attr_name] = epoch_to_utc(epoch)
        else:
            attr_map[artifact_id][attr_name] = raw_value

    # Build normalized records
    records = []
    for (artifact_id, type_name,
         parent_path, file_name, file_size) in artifacts_raw:

        attributes    = attr_map.get(artifact_id, {})
        artifact_type = ARTIFACT_TYPE_MAP.get(
            type_name, type_name.lower().replace(" ", "_")
        )
        timestamp     = _get_primary_timestamp(attributes)
        description   = _build_description(artifact_type, attributes)

        source_path = ""
        if parent_path and file_name:
            source_path = f"{parent_path}{file_name}"

        records.append({
            "artifact_id":    str(uuid.uuid4()),
            "autopsy_id":     artifact_id,
            "source":         "autopsy",
            "artifact_type":  artifact_type,
            "timestamp_utc":  timestamp,
            "description":    description,
            "source_file":    source_path,
            "raw_data":       attributes,
            "tags":           [],
            "correlated_ids": []
        })

    return records


def run_normalizer(db_path: str,
                   case_id: str = None) -> int:
    """
    Normalize all artifacts from any autopsy.db.
    Output goes to data/normalized/artifacts.jsonl

    Args:
        db_path:  path to any autopsy.db
        case_id:  optional custody case ID

    Returns:
        total number of records written
    """
    print(f"\n  Reading Autopsy database...")
    print(f"  Source: {db_path}")

    records     = load_all_artifacts(db_path)
    type_counts = defaultdict(int)
    for r in records:
        type_counts[r["artifact_type"]] += 1

    print(f"\n  Artifact breakdown:")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t:<40} {c:>5}")

    os.makedirs(NORMALIZED_DIR, exist_ok=True)
    output_path = os.path.join(NORMALIZED_DIR, "artifacts.jsonl")

    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    total = len(records)
    print(f"\n  ✓ Normalization complete")
    print(f"    Total records : {total:,}")
    print(f"    Output        : {output_path}")

    if case_id:
        from automation.ingestion.custody import log_action
        log_action(case_id, "normalization_complete", {
            "db_path":        db_path,
            "output_file":    output_path,
            "total_records":  total,
            "artifact_types": dict(type_counts),
            "status":         "success"
        })

    return total


if __name__ == "__main__":
    import glob

    # Find most recent case in data/cases/
    # Works for ANY case — not specific to Mantooth
    cases = sorted(
        glob.glob(os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "cases", "*"
        )),
        key=os.path.getmtime,
        reverse=True
    )

    if not cases:
        print("No cases found in data/cases/")
        print("Run the pipeline first to create a case.")
        sys.exit(1)

    db_path = os.path.join(cases[0], "autopsy.db")

    if not os.path.exists(db_path):
        print(f"No autopsy.db found in {cases[0]}")
        sys.exit(1)

    print(f"Using: {db_path}")
    total = run_normalizer(db_path)

    # Preview 3 records
    output_path = os.path.join(NORMALIZED_DIR, "artifacts.jsonl")
    print("\n── First 3 normalized records ──────────────")
    with open(output_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= 3:
                break
            r = json.loads(line)
            print(f"\n[{i+1}] {r['artifact_type']}")
            print(f"     Timestamp   : {r['timestamp_utc']}")
            print(f"     Description : {r['description']}")
            print(f"     Source file : {r['source_file']}")