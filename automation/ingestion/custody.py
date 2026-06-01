# automation/ingestion/custody.py
# Chain of custody and audit logging for the DFIR pipeline.
# Append-only JSONL log — one JSON object per line.
# Works for any image, any case, any pipeline run.

import json
import os
import uuid
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
from config import DOCS_DIR

CUSTODY_LOG_PATH = os.path.join(DOCS_DIR, "custody_log.jsonl")


def _get_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_entry(entry: dict) -> None:
    os.makedirs(os.path.dirname(CUSTODY_LOG_PATH), exist_ok=True)
    with open(CUSTODY_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def create_custody_record(image_path: str,
                           sha256: str, md5: str) -> str:
    """
    Create the first custody entry for any forensic image.
    Returns a unique case_id for this pipeline session.
    """
    case_id    = str(uuid.uuid4())
    image_name = os.path.basename(image_path)
    image_size = os.path.getsize(image_path)

    entry = {
        "event":             "image_received",
        "case_id":           case_id,
        "timestamp_utc":     _get_timestamp(),
        "image_name":        image_name,
        "image_path":        os.path.abspath(image_path),
        "image_size_bytes":  image_size,
        "sha256":            sha256,
        "md5":               md5,
        "access_mode":       "read-only",
        "pipeline_version":  "1.0.0"
    }

    _append_entry(entry)
    print(f"  ✓ Custody record created — case_id: {case_id}")
    return case_id


def log_action(case_id: str, event: str, details: dict) -> None:
    """Log any pipeline action to the custody trail."""
    entry = {
        "event":         event,
        "case_id":       case_id,
        "timestamp_utc": _get_timestamp(),
        **details
    }
    _append_entry(entry)


def log_hash_verification(case_id: str, passed: bool,
                           computed: str, expected: str) -> None:
    log_action(case_id, "hash_verification", {
        "passed":   passed,
        "computed": computed,
        "expected": expected,
        "note": "Image integrity confirmed" if passed
                else "INTEGRITY FAILURE — hashes do not match"
    })


def log_parser_run(case_id: str, parser_name: str,
                   output_file: str, records: int,
                   status: str, error: str = None) -> None:
    details = {
        "parser":           parser_name,
        "output_file":      output_file,
        "records_produced": records,
        "status":           status
    }
    if error:
        details["error"] = error
    log_action(case_id, "parser_run", details)


def export_custody_report(output_path: str = None) -> None:
    """Export a human-readable Markdown custody report."""
    if output_path is None:
        output_path = os.path.join(DOCS_DIR, "custody_report.md")

    if not os.path.exists(CUSTODY_LOG_PATH):
        print("  No custody log found.")
        return

    with open(CUSTODY_LOG_PATH, "r", encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    lines = [
        "# DFIR Pipeline — Chain of Custody Report",
        f"Generated: {_get_timestamp()}",
        f"Total events: {len(entries)}",
        "", "---", ""
    ]

    for e in entries:
        lines.append(f"### {e.get('event', 'unknown').upper()}")
        lines.append(f"- **Time:** {e.get('timestamp_utc', 'N/A')}")
        lines.append(f"- **Case ID:** {e.get('case_id', 'N/A')}")
        for k, v in e.items():
            if k not in ("event", "timestamp_utc", "case_id"):
                lines.append(f"- **{k}:** {v}")
        lines.append("")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"  ✓ Custody report written to {output_path}")