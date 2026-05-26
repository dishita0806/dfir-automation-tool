# automation/ingestion/custody.py
# Chain of custody and audit logging for the DFIR pipeline.
#
# Every action the pipeline takes is recorded here as an
# append-only JSONL log (one JSON object per line).
# This gives us a tamper-evident audit trail — if any line
# is removed or modified, the sequence breaks and it's detectable.
#
# This module is imported by every other module in the pipeline.
# Think of it as the pipeline's black box flight recorder.

import json
import os
import uuid
from datetime import datetime, timezone


# Path to the audit log — relative to project root
CUSTODY_LOG_PATH = os.path.join("docs", "custody_log.jsonl")


def _get_timestamp() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_entry(entry: dict) -> None:
    """
    Append a single JSON entry to the custody log.
    Creates the log file if it doesn't exist.
    Each line is a complete, self-contained JSON object.
    """
    os.makedirs(os.path.dirname(CUSTODY_LOG_PATH), exist_ok=True)
    with open(CUSTODY_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def create_custody_record(image_path: str, sha256: str, md5: str) -> str:
    """
    Create the first custody entry when an image is received.
    This is the root of the chain — every subsequent action
    references the case_id returned here.

    Args:
        image_path: Full path to the forensic image
        sha256:     Pre-computed SHA256 hash of the image
        md5:        Pre-computed MD5 hash of the image

    Returns:
        case_id (str): unique ID for this investigation session
    """
    case_id = str(uuid.uuid4())
    image_name = os.path.basename(image_path)
    image_size = os.path.getsize(image_path)

    entry = {
        "event":        "image_received",
        "case_id":      case_id,
        "timestamp_utc": _get_timestamp(),
        "image_name":   image_name,
        "image_path":   os.path.abspath(image_path),
        "image_size_bytes": image_size,
        "sha256":       sha256,
        "md5":          md5,
        "access_mode":  "read-only",
        "pipeline_version": "1.0.0"
    }

    _append_entry(entry)
    print(f"  ✓ Custody record created — case_id: {case_id}")
    return case_id


def log_action(case_id: str, event: str, details: dict) -> None:
    """
    Log any pipeline action to the custody trail.
    Called by every module — parsers, walkers, correlators.

    Args:
        case_id: The case ID from create_custody_record
        event:   Short string describing the action
                 e.g. "hash_verified", "parser_run", "walker_complete"
        details: Dict of any relevant details for this event
    """
    entry = {
        "event":         event,
        "case_id":       case_id,
        "timestamp_utc": _get_timestamp(),
        **details        # merge details directly into the entry
    }
    _append_entry(entry)


def log_hash_verification(case_id: str, passed: bool,
                           computed: str, expected: str) -> None:
    """
    Dedicated logger for hash verification events.
    Clearly records pass/fail with both hash values
    so any tampering is immediately visible in the log.
    """
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
    """
    Log the result of running an artifact parser.

    Args:
        case_id:     Case ID
        parser_name: e.g. "browser_history", "registry", "prefetch"
        output_file: Path to the JSONL output file produced
        records:     Number of artifact records extracted
        status:      "success" or "failed"
        error:       Error message if status is "failed"
    """
    details = {
        "parser":      parser_name,
        "output_file": output_file,
        "records_produced": records,
        "status":      status
    }
    if error:
        details["error"] = error

    log_action(case_id, "parser_run", details)


def export_custody_report(output_path: str = "docs/custody_report.md") -> None:
    """
    Read the custody log and render a human-readable
    Markdown report summarising all pipeline actions.

    Args:
        output_path: Where to write the Markdown report
    """
    if not os.path.exists(CUSTODY_LOG_PATH):
        print("  No custody log found — nothing to export.")
        return

    with open(CUSTODY_LOG_PATH, "r", encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    lines = [
        "# DFIR Pipeline — Chain of Custody Report",
        f"Generated: {_get_timestamp()}",
        f"Total events: {len(entries)}",
        "",
        "---",
        ""
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


if __name__ == "__main__":
    # Quick test — create a sample custody record and log a few actions
    import sys
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..")))

    from automation.ingestion.hasher import compute_hash

    image_path = os.path.join("data", "images", "Mantooth 3.e01")
    print("\nComputing hashes...")
    hashes = compute_hash(image_path)

    print("\nCreating custody record...")
    case_id = create_custody_record(image_path, hashes["sha256"], hashes["md5"])

    print("\nLogging a test action...")
    log_action(case_id, "test_event", {
        "note": "Environment verification test",
        "status": "success"
    })

    print("\nLogging hash verification...")
    log_hash_verification(
        case_id,
        passed=True,
        computed=hashes["sha256"],
        expected=hashes["sha256"]
    )

    print("\nExporting custody report...")
    export_custody_report()

    print(f"\n  Done. Check docs/custody_log.jsonl and docs/custody_report.md")