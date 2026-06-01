# automation/workflows/autopsy_runner.py
# Runs Autopsy headless on any forensic image.
# Completely general — works with any image dropped into data/images/

import os
import sys
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
from config import AUTOPSY_EXE, AUTOPSY_TIMEOUT, CASES_DIR


def _get_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_case_dir(base_dir: str, case_name: str) -> str:
    """
    Find the case directory Autopsy created.
    Autopsy appends a timestamp — e.g. 'case_2026_05_29_01_10_36'
    Returns the most recently created match.
    """
    base   = Path(base_dir)
    matches = sorted(
        [d for d in base.iterdir()
         if d.is_dir() and d.name.startswith(case_name)],
        key=lambda d: d.stat().st_mtime,
        reverse=True
    )
    if not matches:
        raise FileNotFoundError(
            f"No case directory found for '{case_name}' in {base_dir}"
        )
    return str(matches[0])


def run_autopsy(image_path: str,
                case_name: str = None,
                case_id:   str = None) -> dict:
    """
    Run Autopsy headless on any forensic image.

    Args:
        image_path: absolute path to any forensic image
        case_name:  optional case name (auto-generated if None)
        case_id:    optional custody case ID for logging

    Returns:
        dict with case_dir, db_path, case_name, elapsed, status
    """
    # Auto-generate case name from image filename
    if not case_name:
        image_stem = Path(image_path).stem.replace(" ", "_")
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        case_name  = f"{image_stem}_{timestamp}"

    os.makedirs(CASES_DIR, exist_ok=True)

    print(f"\n  Image     : {os.path.basename(image_path)}")
    print(f"  Case name : {case_name}")
    print(f"  Cases dir : {CASES_DIR}")
    print(f"  Started   : {_get_timestamp()}")
    print(f"\n  Running Autopsy ingest — this may take several minutes...")

    start_time = time.time()

    cmd = [
        AUTOPSY_EXE,
        f'--createCase',
        f'--caseName={case_name}',
        f'--caseBaseDir={CASES_DIR}',
        f'--addDataSource',
        f'--dataSourcePath={image_path}',
        f'--runIngest'
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=AUTOPSY_TIMEOUT
        )

        elapsed  = time.time() - start_time
        case_dir = _find_case_dir(CASES_DIR, case_name)
        db_path  = os.path.join(case_dir, "autopsy.db")

        if not os.path.exists(db_path):
            raise FileNotFoundError(
                f"autopsy.db not found — ingest may have failed"
            )

        print(f"\n  ✓ Autopsy ingest complete")
        print(f"    Elapsed  : {elapsed:.1f}s")
        print(f"    Case dir : {case_dir}")
        print(f"    Database : {db_path}")

        if case_id:
            from automation.ingestion.custody import log_action
            log_action(case_id, "autopsy_ingest_complete", {
                "case_name":       case_name,
                "case_dir":        case_dir,
                "db_path":         db_path,
                "elapsed_seconds": round(elapsed, 2),
                "status":          "success"
            })

        return {
            "case_dir":  case_dir,
            "db_path":   db_path,
            "case_name": case_name,
            "elapsed":   elapsed,
            "status":    "success"
        }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        print(f"\n  ✗ Autopsy timed out after {elapsed:.0f}s")
        return {"status": "failed", "reason": "timeout"}

    except Exception as e:
        print(f"\n  ✗ Autopsy failed: {e}")
        return {"status": "failed", "reason": str(e)}


def get_artifact_summary(db_path: str) -> dict:
    """
    Returns artifact type counts from any autopsy.db.
    """
    import sqlite3
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT bat.display_name, COUNT(*) as count
        FROM blackboard_artifacts ba
        JOIN blackboard_artifact_types bat
            ON ba.artifact_type_id = bat.artifact_type_id
        GROUP BY bat.display_name
        ORDER BY count DESC
    """).fetchall()
    conn.close()
    return {name: count for name, count in rows}