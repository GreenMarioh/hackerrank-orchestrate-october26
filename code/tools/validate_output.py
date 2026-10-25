"""Independent Output Contract Invariant Validator for Ghost Data Still Exists.

Enforces all constraints defined in problem_statement.md and AGENTS.md §6.3, §6.4, §6.5, §6.6, §6.7:
1. Exact CSV header: `case_id,deletion_status,steps_json`
2. Exactly 518 data rows matching the exact set of case_ids in dataset/deletion_requests.csv.
3. Natural numeric sort order for case_id.
4. Valid deletion_status enum: COMPLETE | INCOMPLETE | NOT_APPLICABLE.
5. For NOT_APPLICABLE: steps_json is empty array [].
6. For COMPLETE:
   - Only VERIFICATION phase steps.
   - Non-empty evidence_id.
   - Evidence citation temporal anti-leak: evidence captured at or before case audit_at.
7. For INCOMPLETE:
   - Strictly ordered phases: FINDING -> REMEDIATION -> VERIFICATION.
   - FINDING steps cite non-empty evidence_id captured at or before audit_at.
   - REMEDIATION steps have evidence_id == "".
   - Future VERIFICATION steps have evidence_id == "".
8. Allowed operations and valid state values per phase (AGENTS.md §6.4).
9. Consecutive 1-indexed step_no (1, 2, ..., N).
10. Valid JSON array format with exact 7 keys per step dict.

Usage:
    python code/tools/validate_output.py [output.csv] [--dataset-dir dataset]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DATASET_DIR = REPO_ROOT / "dataset"
DEFAULT_OUTPUT_CSV = REPO_ROOT / "output.csv"

# Contract Enum Definitions (AGENTS.md §6.3, §6.4)
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

ALLOWED_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}

ALLOWED_FINDING_OPS = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
}

ALLOWED_REMEDIATION_OPS = {
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
}

ALLOWED_VERIFICATION_OPS = {
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

STEP_REQUIRED_KEYS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


def parse_iso(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def validate_output(output_path: Path, dataset_dir: Path) -> tuple[bool, list[str]]:
    """Validate output CSV against all contract invariants. Returns (is_valid, list of errors)."""
    errors: list[str] = []

    if not output_path.exists():
        return False, [f"Output file does not exist: {output_path}"]

    # 1. Load dataset context: deletion_requests and evidence manifest
    requests_csv = dataset_dir / "deletion_requests.csv"
    manifest_csv = dataset_dir / "evidence_files.csv"
    activity_csv = dataset_dir / "system_activity.csv"

    if not requests_csv.exists():
        return False, [f"deletion_requests.csv missing from {dataset_dir}"]

    expected_requests: dict[str, dict[str, Any]] = {}
    with open(requests_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            cid = r["case_id"].strip()
            expected_requests[cid] = {
                "audit_at": parse_iso(r["audit_at"].strip()),
                "email": r["email"].strip(),
            }

    expected_count = len(expected_requests)

    # Load evidence capture times
    evidence_times: dict[str, datetime] = {}
    if manifest_csv.exists():
        with open(manifest_csv, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                fid = r["file_id"].strip()
                if "captured_at" in r:
                    evidence_times[fid] = parse_iso(r["captured_at"].strip())

    # Load activity times
    activity_times: dict[str, datetime] = {}
    if activity_csv.exists():
        with open(activity_csv, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                aid = r["activity_id"].strip()
                if "event_time" in r:
                    activity_times[aid] = parse_iso(r["event_time"].strip())

    # 2. Check CSV Header and Rows
    rows: list[dict[str, str]] = []
    with open(output_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return False, ["Output file is completely empty."]

        expected_header = ["case_id", "deletion_status", "steps_json"]
        if header != expected_header:
            errors.append(f"Header mismatch. Expected {expected_header}, got {header}")

        for line_num, r in enumerate(reader, start=2):
            if len(r) != 3:
                errors.append(f"Line {line_num}: Expected 3 columns, found {len(r)}")
                continue
            rows.append({
                "case_id": r[0].strip(),
                "deletion_status": r[1].strip(),
                "steps_json": r[2].strip(),
            })

    # 3. Check Row Count
    if len(rows) != expected_count:
        errors.append(f"Row count mismatch: expected exactly {expected_count} rows, got {len(rows)}")

    # 4. Check Case ID set and order
    actual_cids = [r["case_id"] for r in rows]
    expected_cids = list(expected_requests.keys())

    # Natural numeric order
    def case_sort_key(cid: str) -> int:
        parts = cid.split("_")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    sorted_expected_cids = sorted(expected_cids, key=case_sort_key)

    if actual_cids != sorted_expected_cids:
        if set(actual_cids) != set(expected_cids):
            missing = set(expected_cids) - set(actual_cids)
            extra = set(actual_cids) - set(expected_cids)
            if missing:
                errors.append(f"Missing case_ids in output: {sorted(list(missing))[:10]}")
            if extra:
                errors.append(f"Unexpected case_ids in output: {sorted(list(extra))[:10]}")
        else:
            errors.append("case_ids are not in natural sorted order.")

    # 5. Row-level and Step-level validation
    for r in rows:
        cid = r["case_id"]
        status = r["deletion_status"]
        steps_raw = r["steps_json"]

        req_info = expected_requests.get(cid)
        audit_at = req_info["audit_at"] if req_info else None

        # Check status enum
        if status not in ALLOWED_STATUSES:
            errors.append(f"{cid}: Invalid deletion_status '{status}'. Must be one of {ALLOWED_STATUSES}")
            continue

        # Check JSON parsing
        try:
            steps = json.loads(steps_raw)
        except json.JSONDecodeError as e:
            errors.append(f"{cid}: Invalid JSON in steps_json: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json must be a JSON array, got {type(steps).__name__}")
            continue

        # NOT_APPLICABLE rule: steps_json must be empty
        if status == "NOT_APPLICABLE":
            if len(steps) != 0:
                errors.append(f"{cid}: Status is NOT_APPLICABLE but steps_json is not empty ({len(steps)} steps)")
            continue

        # COMPLETE / INCOMPLETE rules
        if status == "COMPLETE":
            # Must only have VERIFICATION steps
            for s in steps:
                if not isinstance(s, dict):
                    errors.append(f"{cid}: Step is not a dictionary: {s}")
                    continue
                if s.get("phase") != "VERIFICATION":
                    errors.append(f"{cid}: COMPLETE case contains non-VERIFICATION step: {s.get('phase')}")
                # COMPLETE steps must cite valid evidence proving the state
                if not s.get("evidence_id"):
                    errors.append(f"{cid}: COMPLETE verification step missing evidence_id: {s}")

        elif status == "INCOMPLETE":
            # Phases must be ordered: FINDING -> REMEDIATION -> VERIFICATION
            phases_seen = []
            for s in steps:
                if isinstance(s, dict):
                    phases_seen.append(s.get("phase"))

            # Validate phase order
            last_phase_order = 0
            phase_order_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
            for p in phases_seen:
                order = phase_order_map.get(p, 99)
                if order < last_phase_order:
                    errors.append(f"{cid}: Phase out of order: saw {p} after phase with order {last_phase_order}")
                    break
                last_phase_order = order

        # Validate each individual step
        for idx, s in enumerate(steps, start=1):
            if not isinstance(s, dict):
                continue

            # Check keys
            missing_keys = STEP_REQUIRED_KEYS - set(s.keys())
            if missing_keys:
                errors.append(f"{cid} Step {idx}: Missing required keys {missing_keys}")

            # Check 1-indexed consecutive numbering
            step_no = s.get("step_no")
            if step_no != idx:
                errors.append(f"{cid}: Expected step_no {idx}, found {step_no}")

            phase = s.get("phase")
            op = s.get("operation")
            st = s.get("state")
            eid = s.get("evidence_id", "")

            # Check allowed operations & states per phase
            if phase == "FINDING":
                if op not in ALLOWED_FINDING_OPS:
                    errors.append(f"{cid} Step {idx}: Invalid finding operation '{op}'")
                elif st != ALLOWED_FINDING_OPS[op]:
                    errors.append(f"{cid} Step {idx}: State '{st}' invalid for finding op '{op}' (expected '{ALLOWED_FINDING_OPS[op]}')")
                if not eid:
                    errors.append(f"{cid} Step {idx}: Finding step must have non-empty evidence_id")

            elif phase == "REMEDIATION":
                if op not in ALLOWED_REMEDIATION_OPS:
                    errors.append(f"{cid} Step {idx}: Invalid remediation operation '{op}'")
                elif st != ALLOWED_REMEDIATION_OPS[op]:
                    errors.append(f"{cid} Step {idx}: State '{st}' invalid for remediation op '{op}' (expected '{ALLOWED_REMEDIATION_OPS[op]}')")
                if eid != "":
                    errors.append(f"{cid} Step {idx}: Future remediation step must have empty evidence_id, got '{eid}'")

            elif phase == "VERIFICATION":
                if op not in ALLOWED_VERIFICATION_OPS:
                    errors.append(f"{cid} Step {idx}: Invalid verification operation '{op}'")
                elif st != ALLOWED_VERIFICATION_OPS[op]:
                    errors.append(f"{cid} Step {idx}: State '{st}' invalid for verification op '{op}' (expected '{ALLOWED_VERIFICATION_OPS[op]}')")
                if status == "INCOMPLETE" and eid != "":
                    errors.append(f"{cid} Step {idx}: Post-remediation verification step must have empty evidence_id, got '{eid}'")

            else:
                errors.append(f"{cid} Step {idx}: Invalid phase '{phase}'")

            # Check temporal anti-leak on cited evidence
            if eid and audit_at:
                t_captured = evidence_times.get(eid) or activity_times.get(eid)
                if t_captured and t_captured > audit_at:
                    errors.append(
                        f"{cid} Step {idx}: Temporal citation leak! Evidence '{eid}' captured at {t_captured.isoformat()} > audit_at {audit_at.isoformat()}"
                    )

    is_valid = len(errors) == 0
    return is_valid, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate output.csv against submission contract.")
    parser.add_argument(
        "output_path",
        type=Path,
        nargs="?",
        default=DEFAULT_OUTPUT_CSV,
        help="Path to output.csv to validate (default: output.csv at repo root)",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help="Path to dataset directory (default: dataset)",
    )
    args = parser.parse_args()

    print(f"Validating {args.output_path} against dataset in {args.dataset_dir}...")
    is_valid, errors = validate_output(args.output_path, args.dataset_dir)

    if is_valid:
        print("ALL OUTPUT INVARIANTS PASSED.")
        print(f"Verified 518 cases with 100% schema, phase, operation, numbering, and temporal compliance.")
        sys.exit(0)
    else:
        print(f"VALIDATION FAILED with {len(errors)} errors:")
        for err in errors[:25]:
            print(f"  - {err}")
        if len(errors) > 25:
            print(f"  ... and {len(errors) - 25} more errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
