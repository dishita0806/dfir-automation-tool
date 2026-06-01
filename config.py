# config.py
# Central configuration for the DFIR pipeline.
# Change paths here — applies everywhere automatically.
# This is the ONLY file with specific paths.

import os

# ── Autopsy ───────────────────────────────────────────────────
AUTOPSY_EXE     = r"C:\Program Files\Autopsy-4.23.1\bin\autopsy64.exe"
AUTOPSY_TIMEOUT = 3600  # seconds — increase for very large images

# ── Project root ──────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# ── Data directories ──────────────────────────────────────────
IMAGES_DIR     = os.path.join(PROJECT_ROOT, "data", "images")
CASES_DIR      = os.path.join(PROJECT_ROOT, "data", "cases")
EXTRACTED_DIR  = os.path.join(PROJECT_ROOT, "data", "extracted")
NORMALIZED_DIR = os.path.join(PROJECT_ROOT, "data", "normalized")
DOCS_DIR       = os.path.join(PROJECT_ROOT, "docs")

# ── Tools ─────────────────────────────────────────────────────
PECMD_EXE    = os.path.join(PROJECT_ROOT, "tools", "zimmerman",
                             "PECmd", "PECmd.exe")
JLECMD_EXE   = os.path.join(PROJECT_ROOT, "tools", "zimmerman",
                             "JLECmd", "JLECmd.exe")
CHAINSAW_EXE = os.path.join(PROJECT_ROOT, "tools", "chainsaw",
                             "chainsaw", "chainsaw.exe")

# ── Pipeline defaults ─────────────────────────────────────────
PIPELINE_VERSION = "1.0.0"