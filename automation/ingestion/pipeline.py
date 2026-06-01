# automation/ingestion/pipeline.py
# Master pipeline — orchestrates the full DFIR automation flow.
# Completely general — works with any forensic image.
#
# Usage:
#   python automation/ingestion/pipeline.py
#   python automation/ingestion/pipeline.py <image_path>

import os
import sys
import time
import json
from colorama import init, Fore, Style

init(autoreset=True)

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from config import IMAGES_DIR, CASES_DIR, NORMALIZED_DIR
from automation.ingestion.detector  import detect_format
from automation.ingestion.hasher    import compute_hash
from automation.ingestion.custody   import (
    create_custody_record, log_action,
    log_hash_verification, export_custody_report
)
from automation.workflows.autopsy_runner   import run_autopsy
from automation.workflows.normalizer       import run_normalizer
from automation.workflows.report_generator import generate_report


def banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════════════════════╗
║           DFIR Automation Pipeline v1.0              ║
║     Autopsy + Normalization + RAG-ready output       ║
╚══════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)


def step(n: int, title: str):
    print(Fore.YELLOW + f"\n[Step {n}] {title}" + Style.RESET_ALL)


def ok(msg: str):
    print(Fore.GREEN + f"  ✓ {msg}" + Style.RESET_ALL)


def fail(msg: str):
    print(Fore.RED + f"  ✗ {msg}" + Style.RESET_ALL)


def info(msg: str):
    print(f"    {msg}")


def run_pipeline(image_path: str) -> dict:
    """
    Run the full pipeline on any forensic image.

    Args:
        image_path: path to any E01 or RAW forensic image

    Returns:
        dict with case_id, hashes, db_path, total_records, elapsed
    """
    banner()
    start_time = time.time()

    # ── Step 1: Detect format ─────────────────────────────────
    step(1, "Detecting image format")
    fmt = detect_format(image_path)
    ok(f"Format : {fmt.upper()}")
    info(f"Image  : {os.path.basename(image_path)}")
    info(f"Size   : {os.path.getsize(image_path)/(1024**2):.1f} MB")

    # ── Step 2: Compute hashes ────────────────────────────────
    step(2, "Computing cryptographic hashes")
    hashes = compute_hash(image_path)
    ok(f"MD5    : {hashes['md5']}")
    ok(f"SHA256 : {hashes['sha256']}")

    # ── Step 3: Create custody record ────────────────────────
    step(3, "Creating chain of custody record")
    case_id = create_custody_record(
        image_path, hashes["sha256"], hashes["md5"]
    )
    ok(f"Case ID : {case_id}")

    # ── Step 4: Record integrity hash ────────────────────────
    step(4, "Recording image integrity hash")
    log_action(case_id, "hash_recorded", {
        "sha256": hashes["sha256"],
        "md5":    hashes["md5"],
        "note":   "Hash recorded at ingestion for audit trail"
    })
    ok("Hash recorded in custody log")

    # ── Step 5: Run Autopsy ───────────────────────────────────
    step(5, "Running Autopsy ingest")
    autopsy_result = run_autopsy(
        image_path = os.path.abspath(image_path),
        case_id    = case_id
    )

    if autopsy_result["status"] != "success":
        fail(f"Autopsy failed: {autopsy_result.get('reason')}")
        sys.exit(1)

    db_path = autopsy_result["db_path"]
    ok(f"Autopsy complete — {autopsy_result['elapsed']:.1f}s")
    ok(f"Database : {db_path}")

    # ── Step 6: Normalize artifacts ───────────────────────────
    step(6, "Normalizing Autopsy artifacts")
    total = run_normalizer(db_path, case_id=case_id)
    ok(f"Normalized {total:,} artifacts")

    # ── Step 7: Generate investigation report ────────────────
    step(7, "Generating investigation report")
    report_path = generate_report(case_id=case_id)
    if report_path:
        ok(f"Report written : {report_path}")
    else:
        ok("Report skipped — no artifacts found")

    # ── Step 8: Wrap up ───────────────────────────────────────
    step(7, "Finalising pipeline run")
    elapsed = time.time() - start_time

    log_action(case_id, "pipeline_complete", {
        "elapsed_seconds": round(elapsed, 2),
        "total_artifacts": total,
        "db_path":         db_path,
        "status":          "success"
    })

    export_custody_report()

    ok(f"Pipeline complete in {elapsed:.1f}s")
    ok(f"Artifacts normalized : {total:,}")
    ok(f"Report               : docs/investigation_report.txt")
    ok(f"Custody log          : docs/custody_log.jsonl")
    ok(f"Normalized output    : data/normalized/artifacts.jsonl")

    print(Fore.CYAN +
          "\n══════════════════════════════════════════════════════\n"
          + Style.RESET_ALL)

    return {
        "case_id":       case_id,
        "hashes":        hashes,
        "db_path":       db_path,
        "total_records": total,
        "elapsed":       elapsed
    }


if __name__ == "__main__":
    # Accept any image path as argument
    # Falls back to first image found in data/images/
    if len(sys.argv) > 1:
        image = sys.argv[1]
    else:
        # Auto-find first image in data/images/
        images = [
            f for f in os.listdir(IMAGES_DIR)
            if f.lower().endswith((".e01", ".dd", ".raw", ".img"))
        ]
        if not images:
            print(Fore.RED +
                  f"  No images found in {IMAGES_DIR}" +
                  Style.RESET_ALL)
            sys.exit(1)
        image = os.path.join(IMAGES_DIR, images[0])

    if not os.path.exists(image):
        print(Fore.RED + f"  Image not found: {image}" + Style.RESET_ALL)
        sys.exit(1)

    run_pipeline(image)