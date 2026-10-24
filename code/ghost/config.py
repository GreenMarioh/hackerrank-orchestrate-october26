"""
config.py — paths, constants, model names.

All paths are resolved relative to the repo root so the solution works
on macOS, Linux, and Windows without modification.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# ── Repo layout ────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent.parent   # …/hackerrank-…-main/
load_dotenv(REPO_ROOT / ".env")
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
CODE_DIR = REPO_ROOT / "code"
CACHE_DIR = REPO_ROOT / ".cache"
OUTPUT_PATH = REPO_ROOT / "output.csv"                      # final submission file

# ── Dataset files (all read-only during prediction) ───────────────────────────
DELETION_REQUESTS_CSV = DATASET_DIR / "deletion_requests.csv"
DELETION_RULES_CSV    = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_CSV    = DATASET_DIR / "evidence_files.csv"
USER_IDENTITIES_CSV   = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_CSV    = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_CSV   = DATASET_DIR / "system_activity.csv"

# ── Dev-only files (evaluation harness only — never read by main.py prediction) ──
SAMPLE_REQUESTS_CSV = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_CSV = SAMPLE_REQUESTS_CSV
SAMPLE_OUTPUT_CSV   = DATASET_DIR / "sample_output.csv"

# ── Output sort ────────────────────────────────────────────────────────────────
# ASSUMPTION: case_id rows are sorted with plain Python sorted() (lexicographic).
# If numeric sort is needed, change CASE_ID_SORT_KEY to:
#   lambda cid: int(cid.split("_")[-1])
# Document any change in README.md.
CASE_ID_SORT_KEY = str   # plain string sort

# ── Model / LLM settings (read from env) ──────────────────────────────────────
def get_llm_api_key() -> str:
    return os.getenv("LLM_API_KEY", "").strip()

def get_llm_model() -> str:
    return os.getenv("LLM_MODEL", "gemini-2.0-flash").strip()

def is_skip_images() -> bool:
    return os.getenv("SKIP_IMAGE_EXTRACTION", "").strip().lower() in ("1", "true", "yes")

LLM_API_KEY   = get_llm_api_key()
LLM_MODEL     = get_llm_model()
SKIP_IMAGES   = is_skip_images()

# ── Linking / state constants ─────────────────────────────────────────────────
# Candidate time-window radius around reported_at (seconds).  H1 to be confirmed.
LINK_WINDOW_SECONDS = 7200   # 2 hours — candidate generation only

# ── Allowed enumerations (single source of truth) ────────────────────────────
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

OPERATION_ORDER = {
    # FINDING
    "REPORT_REMAINING_RECORD":  0,
    "REPORT_EXPOSED_PII":       1,
    "REPORT_ACTIVE_DATA_FLOW":  2,
    "REPORT_RESTORE_RISK":      3,
    # REMEDIATION
    "DISABLE_DATA_FLOW":        0,
    "BLOCK_RESTORE":            1,
    "DELETE_RECORD":            2,
    "REDACT_RECORD":            3,
    "ANONYMIZE_RECORD":         4,
    # VERIFICATION
    "VERIFY_RECORD_ABSENT":     0,
    "VERIFY_RECORD_PRESENT":    1,
    "VERIFY_RECORD_REDACTED":   2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED":4,
    "VERIFY_RESTORE_BLOCKED":   5,
}

ALLOWED_OPERATIONS: dict[str, tuple[str, str]] = {
    # op -> (phase, state)
    "REPORT_REMAINING_RECORD":  ("FINDING",      "PRESENT"),
    "REPORT_EXPOSED_PII":       ("FINDING",      "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW":  ("FINDING",      "ACTIVE"),
    "REPORT_RESTORE_RISK":      ("FINDING",      "ACTIVE"),
    "DISABLE_DATA_FLOW":        ("REMEDIATION",  "DISABLED"),
    "BLOCK_RESTORE":            ("REMEDIATION",  "BLOCKED"),
    "DELETE_RECORD":            ("REMEDIATION",  "ABSENT"),
    "REDACT_RECORD":            ("REMEDIATION",  "REDACTED"),
    "ANONYMIZE_RECORD":         ("REMEDIATION",  "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT":     ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT":    ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED":   ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED":("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED":   ("VERIFICATION", "BLOCKED"),
}

STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
