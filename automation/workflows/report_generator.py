# automation/workflows/report_generator.py
# Generates a human-readable text report from normalized artifacts.
# Reads data/normalized/artifacts.jsonl and produces
# docs/investigation_report.txt
#
# This report is:
# 1. Human readable — investigator can review it directly
# 2. LLM ready — can be fed directly to the RAG system
# 3. Fully general — works for any image, any case

import os
import sys
import json
from datetime import datetime, timezone
from collections import defaultdict

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
from config import NORMALIZED_DIR, DOCS_DIR


def _get_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_artifacts(artifacts_path: str) -> list:
    records = []
    with open(artifacts_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _section(title: str, width: int = 60) -> str:
    return f"\n{'='*width}\n{title}\n{'='*width}\n"


def _subsection(title: str, width: int = 60) -> str:
    return f"\n{'-'*width}\n{title}\n{'-'*width}\n"


def generate_report(artifacts_path: str = None,
                    output_path:    str = None,
                    case_id:        str = None) -> str:
    """
    Generate a complete investigation report from normalized artifacts.

    Args:
        artifacts_path: path to artifacts.jsonl (auto-detected if None)
        output_path:    where to write the report (auto if None)
        case_id:        custody case ID for logging

    Returns:
        path to the generated report file
    """
    # Auto-detect paths if not provided
    if artifacts_path is None:
        artifacts_path = os.path.join(NORMALIZED_DIR, "artifacts.jsonl")

    if output_path is None:
        output_path = os.path.join(DOCS_DIR, "investigation_report.txt")

    if not os.path.exists(artifacts_path):
        print(f"  No artifacts found at {artifacts_path}")
        print(f"  Run the pipeline first.")
        return None

    print(f"\n  Reading artifacts from: {artifacts_path}")
    records = _load_artifacts(artifacts_path)
    print(f"  Total artifacts: {len(records):,}")

    # Group by artifact type
    by_type = defaultdict(list)
    for r in records:
        by_type[r["artifact_type"]].append(r)

    # Sort artifacts by timestamp where available
    def sort_key(r):
        ts = r.get("timestamp_utc", "N/A")
        return ts if ts != "N/A" else "9999"

    lines = []

    # ── Header ────────────────────────────────────────────────
    lines.append("=" * 60)
    lines.append("DFIR AUTOMATED INVESTIGATION REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated     : {_get_timestamp()}")
    lines.append(f"Artifacts file: {artifacts_path}")
    lines.append(f"Total artifacts: {len(records):,}")
    if case_id:
        lines.append(f"Case ID       : {case_id}")
    lines.append("")

    # ── Executive Summary ─────────────────────────────────────
    lines.append(_section("EXECUTIVE SUMMARY"))

    lines.append(f"Total artifacts extracted : {len(records):,}")
    lines.append("")
    lines.append("Artifact breakdown:")
    for art_type, arts in sorted(
            by_type.items(), key=lambda x: -len(x[1])):
        display = art_type.replace("_", " ").title()
        lines.append(f"  {display:<35} {len(arts):>5}")

    # ── Key Findings ──────────────────────────────────────────
    lines.append(_section("KEY FINDINGS"))

    # USB devices
    if "usb_device" in by_type:
        lines.append(f"[!] {len(by_type['usb_device'])} USB device(s) "
                     f"connected to this machine")

    # Encryption
    if "encryption_detected" in by_type:
        lines.append(f"[!] Encryption detected in "
                     f"{len(by_type['encryption_detected'])} file(s)")

    # Deleted files
    if "recycle_bin" in by_type:
        lines.append(f"[!] {len(by_type['recycle_bin'])} file(s) "
                     f"found in Recycle Bin")

    # Extension mismatches
    if "extension_mismatch" in by_type:
        lines.append(f"[!] {len(by_type['extension_mismatch'])} "
                     f"file(s) with mismatched extensions — "
                     f"possible file hiding")

    # Web searches
    if "web_search" in by_type:
        lines.append(f"[i] {len(by_type['web_search'])} web search(es) "
                     f"recorded")

    # Emails
    if "email_message" in by_type:
        lines.append(f"[i] {len(by_type['email_message'])} email "
                     f"message(s) found")

    lines.append("")

    # ── Web History ───────────────────────────────────────────
    if "web_history" in by_type:
        lines.append(_section(
            f"WEB HISTORY ({len(by_type['web_history'])} records)"
        ))
        sorted_arts = sorted(by_type["web_history"], key=sort_key)
        for r in sorted_arts:
            ts  = r.get("timestamp_utc", "N/A")
            url = r["raw_data"].get("URL", "N/A")
            ttl = r["raw_data"].get("Title", "")
            dom = r["raw_data"].get("Domain", "")
            lines.append(f"  [{ts}]")
            lines.append(f"    URL    : {url}")
            if ttl:
                lines.append(f"    Title  : {ttl}")
            if dom:
                lines.append(f"    Domain : {dom}")
            lines.append("")

    # ── Web Searches ──────────────────────────────────────────
    if "web_search" in by_type:
        lines.append(_section(
            f"WEB SEARCHES ({len(by_type['web_search'])} records)"
        ))
        sorted_arts = sorted(by_type["web_search"], key=sort_key)
        for r in sorted_arts:
            ts    = r.get("timestamp_utc", "N/A")
            query = r["raw_data"].get("Text",
                    r["raw_data"].get("URL", "N/A"))
            prog  = r["raw_data"].get("Program Name", "")
            lines.append(f"  [{ts}] {query}")
            if prog:
                lines.append(f"    via: {prog}")
            lines.append("")

    # ── USB Devices ───────────────────────────────────────────
    if "usb_device" in by_type:
        lines.append(_section(
            f"USB DEVICES ({len(by_type['usb_device'])} records)"
        ))
        for r in sorted(by_type["usb_device"], key=sort_key):
            ts     = r.get("timestamp_utc", "N/A")
            device = r["raw_data"].get("Display Name",
                     r["raw_data"].get("Device ID", "N/A"))
            serial = r["raw_data"].get("Device ID", "N/A")
            lines.append(f"  [{ts}]")
            lines.append(f"    Device : {device}")
            lines.append(f"    Serial : {serial}")
            lines.append("")

    # ── Recycle Bin (Deleted Files) ───────────────────────────
    if "recycle_bin" in by_type:
        lines.append(_section(
            f"DELETED FILES — RECYCLE BIN "
            f"({len(by_type['recycle_bin'])} records)"
        ))
        for r in sorted(by_type["recycle_bin"], key=sort_key):
            ts   = r.get("timestamp_utc", "N/A")
            path = r["raw_data"].get("Path", "N/A")
            lines.append(f"  [{ts}]")
            lines.append(f"    Path : {path}")
            lines.append("")

    # ── Run Programs ──────────────────────────────────────────
    if "run_program" in by_type:
        lines.append(_section(
            f"PROGRAMS EXECUTED ({len(by_type['run_program'])} records)"
        ))
        for r in sorted(by_type["run_program"], key=sort_key):
            ts   = r.get("timestamp_utc", "N/A")
            prog = r["raw_data"].get("Program Name",
                   r["raw_data"].get("Path", "N/A"))
            cnt  = r["raw_data"].get("Run Count", "")
            lines.append(f"  [{ts}]")
            lines.append(f"    Program   : {prog}")
            if cnt:
                lines.append(f"    Run count : {cnt}")
            lines.append("")

    # ── Recent Documents ──────────────────────────────────────
    if "recent_document" in by_type:
        lines.append(_section(
            f"RECENTLY OPENED FILES "
            f"({len(by_type['recent_document'])} records)"
        ))
        for r in sorted(by_type["recent_document"], key=sort_key):
            ts   = r.get("timestamp_utc", "N/A")
            path = r["raw_data"].get("Path", "N/A")
            lines.append(f"  [{ts}] {path}")
        lines.append("")

    # ── Installed Programs ────────────────────────────────────
    if "installed_program" in by_type:
        lines.append(_section(
            f"INSTALLED PROGRAMS "
            f"({len(by_type['installed_program'])} records)"
        ))
        for r in sorted(by_type["installed_program"], key=sort_key):
            name    = r["raw_data"].get("Program Name", "N/A")
            version = r["raw_data"].get("Version", "")
            date    = r["raw_data"].get("Date Installed",
                      r.get("timestamp_utc", ""))
            lines.append(f"  {name}")
            if version:
                lines.append(f"    Version   : {version}")
            if date:
                lines.append(f"    Installed : {date}")
            lines.append("")

    # ── Email Messages ────────────────────────────────────────
    if "email_message" in by_type:
        lines.append(_section(
            f"EMAIL MESSAGES ({len(by_type['email_message'])} records)"
        ))
        for r in sorted(by_type["email_message"], key=sort_key):
            ts      = r.get("timestamp_utc", "N/A")
            subject = r["raw_data"].get("Subject", "N/A")
            sender  = r["raw_data"].get("Sender", "N/A")
            recip   = r["raw_data"].get("Recipient", "")
            lines.append(f"  [{ts}]")
            lines.append(f"    Subject : {subject}")
            lines.append(f"    From    : {sender}")
            if recip:
                lines.append(f"    To      : {recip}")
            lines.append("")

    # ── Encryption Detected ───────────────────────────────────
    if "encryption_detected" in by_type:
        lines.append(_section(
            f"ENCRYPTION DETECTED "
            f"({len(by_type['encryption_detected'])} records)"
        ))
        for r in by_type["encryption_detected"]:
            name    = r["raw_data"].get("Name", "N/A")
            comment = r["raw_data"].get("Comment", "")
            lines.append(f"  File    : {name}")
            if comment:
                lines.append(f"  Comment : {comment}")
            lines.append("")

    # ── Extension Mismatches ──────────────────────────────────
    if "extension_mismatch" in by_type:
        lines.append(_section(
            f"EXTENSION MISMATCHES "
            f"({len(by_type['extension_mismatch'])} records)"
        ))
        for r in by_type["extension_mismatch"]:
            src  = r.get("source_file", "N/A")
            ext  = r["raw_data"].get("File Extension", "")
            mime = r["raw_data"].get("MIME Type", "")
            lines.append(f"  File      : {src}")
            if ext:
                lines.append(f"  Extension : {ext}")
            if mime:
                lines.append(f"  MIME type : {mime}")
            lines.append("")

    # ── Accounts ──────────────────────────────────────────────
    if "account" in by_type:
        lines.append(_section(
            f"ACCOUNTS ({len(by_type['account'])} records)"
        ))
        for r in by_type["account"]:
            name = r["raw_data"].get("Account ID",
                   r["raw_data"].get("Display Name", "N/A"))
            atype = r["raw_data"].get("Account Type", "")
            lines.append(f"  Account : {name}")
            if atype:
                lines.append(f"  Type    : {atype}")
            lines.append("")

    # ── Shell Bags ────────────────────────────────────────────
    if "shell_bag" in by_type:
        lines.append(_section(
            f"SHELL BAGS — FOLDER ACCESS HISTORY "
            f"({len(by_type['shell_bag'])} records)"
        ))
        for r in sorted(by_type["shell_bag"], key=sort_key):
            ts   = r.get("timestamp_utc", "N/A")
            path = r["raw_data"].get("Folder Path",
                   r["raw_data"].get("Value Name", "N/A"))
            lines.append(f"  [{ts}] {path}")
        lines.append("")

    # ── Footer ────────────────────────────────────────────────
    lines.append(_section("END OF REPORT"))
    lines.append(f"Report generated: {_get_timestamp()}")
    lines.append(f"Total artifacts : {len(records):,}")
    lines.append("")

    # Write report
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"  ✓ Report written to: {output_path}")

    # Log to custody
    if case_id:
        from automation.ingestion.custody import log_action
        log_action(case_id, "report_generated", {
            "output_file":    output_path,
            "total_artifacts": len(records),
            "status":         "success"
        })

    return output_path


if __name__ == "__main__":
    path = generate_report()
    if path:
        print(f"\n  Open {path} to review the full report")