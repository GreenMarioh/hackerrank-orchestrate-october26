"""Unit tests for Output Contract Validator (code/tools/validate_output.py).

Verifies that the validator accurately enforces and rejects:
1. Malformed headers and row counts.
2. Invalid statuses.
3. NOT_APPLICABLE cases with non-empty steps.
4. COMPLETE cases with non-VERIFICATION phases or missing evidence.
5. INCOMPLETE cases with phase inversion or non-empty future step citations.
6. Temporal citation leaks (captured_at > audit_at).
7. Non-consecutive step_no numbering.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from tools.validate_output import validate_output


@pytest.fixture
def mock_dataset(tmp_path: Path) -> Path:
    """Create a minimal mock dataset directory."""
    ds = tmp_path / "dataset"
    ds.mkdir()

    # deletion_requests.csv with 2 cases
    reqs = [
        {"case_id": "case_01", "email": "a@ex.com", "requested_at": "2026-09-01T00:00:00Z", "reported_status": "COMPLETE", "reported_at": "2026-09-02T00:00:00Z", "audit_at": "2026-09-10T00:00:00Z", "request_text": "delete"},
        {"case_id": "case_02", "email": "b@ex.com", "requested_at": "2026-09-01T00:00:00Z", "reported_status": "NOT_STARTED", "reported_at": "2026-09-02T00:00:00Z", "audit_at": "2026-09-10T00:00:00Z", "request_text": "erase"},
    ]
    with open(ds / "deletion_requests.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(reqs[0].keys()))
        writer.writeheader()
        writer.writerows(reqs)

    # evidence_files.csv with 1 pre-cutoff file and 1 post-cutoff file
    ev = [
        {"file_id": "evidence_01", "file_path": "evidence/records/a.json", "source_origin": "sys", "captured_at": "2026-09-05T00:00:00Z"},
        {"file_id": "evidence_post", "file_path": "evidence/records/post.json", "source_origin": "sys", "captured_at": "2026-09-20T00:00:00Z"},
    ]
    with open(ds / "evidence_files.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(ev[0].keys()))
        writer.writeheader()
        writer.writerows(ev)

    return ds


def write_test_output(path: Path, rows: list[list[str]], header: list[str] | None = None) -> None:
    if header is None:
        header = ["case_id", "deletion_status", "steps_json"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def test_validator_passes_valid_output(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    c1_steps = [
        {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_01", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}
    ]
    c2_steps = [
        {"step_no": 1, "phase": "FINDING", "system_id": "search_service", "resource_id": "search_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
        {"step_no": 2, "phase": "REMEDIATION", "system_id": "search_service", "resource_id": "search_01", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
        {"step_no": 3, "phase": "VERIFICATION", "system_id": "search_service", "resource_id": "search_01", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
    ]

    rows = [
        ["case_01", "COMPLETE", json.dumps(c1_steps)],
        ["case_02", "INCOMPLETE", json.dumps(c2_steps)],
    ]
    write_test_output(out, rows)

    is_valid, errors = validate_output(out, mock_dataset)
    assert is_valid
    assert errors == []


def test_validator_catches_wrong_header(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    write_test_output(out, [], header=["id", "status", "steps"])
    is_valid, errors = validate_output(out, mock_dataset)
    assert not is_valid
    assert any("Header mismatch" in e for e in errors)


def test_validator_catches_row_count_mismatch(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    # Only 1 row instead of expected 2
    write_test_output(out, [["case_01", "NOT_APPLICABLE", "[]"]])
    is_valid, errors = validate_output(out, mock_dataset)
    assert not is_valid
    assert any("Row count mismatch" in e for e in errors)


def test_validator_catches_non_empty_not_applicable(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    step = [{"step_no": 1, "phase": "VERIFICATION", "system_id": "sys", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}]
    rows = [
        ["case_01", "NOT_APPLICABLE", json.dumps(step)],
        ["case_02", "NOT_APPLICABLE", "[]"],
    ]
    write_test_output(out, rows)
    is_valid, errors = validate_output(out, mock_dataset)
    assert not is_valid
    assert any("NOT_APPLICABLE but steps_json is not empty" in e for e in errors)


def test_validator_catches_phase_inversion(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    # REMEDIATION before FINDING
    c2_steps = [
        {"step_no": 1, "phase": "REMEDIATION", "system_id": "search_service", "resource_id": "search_01", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
        {"step_no": 2, "phase": "FINDING", "system_id": "search_service", "resource_id": "search_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
    ]
    rows = [
        ["case_01", "COMPLETE", json.dumps([{"step_no": 1, "phase": "VERIFICATION", "system_id": "acc", "resource_id": "a", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}])],
        ["case_02", "INCOMPLETE", json.dumps(c2_steps)],
    ]
    write_test_output(out, rows)
    is_valid, errors = validate_output(out, mock_dataset)
    assert not is_valid
    assert any("Phase out of order" in e for e in errors)


def test_validator_catches_temporal_citation_leak(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    # evidence_post is captured at 2026-09-20 > audit_at 2026-09-10
    c1_steps = [
        {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_01", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_post"}
    ]
    rows = [
        ["case_01", "COMPLETE", json.dumps(c1_steps)],
        ["case_02", "NOT_APPLICABLE", "[]"],
    ]
    write_test_output(out, rows)
    is_valid, errors = validate_output(out, mock_dataset)
    assert not is_valid
    assert any("Temporal citation leak" in e for e in errors)


def test_validator_catches_non_consecutive_step_numbers(tmp_path: Path, mock_dataset: Path) -> None:
    out = tmp_path / "output.csv"
    c1_steps = [
        {"step_no": 2, "phase": "VERIFICATION", "system_id": "acc", "resource_id": "a", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}
    ]
    rows = [
        ["case_01", "COMPLETE", json.dumps(c1_steps)],
        ["case_02", "NOT_APPLICABLE", "[]"],
    ]
    write_test_output(out, rows)
    is_valid, errors = validate_output(out, mock_dataset)
    assert not is_valid
    assert any("Expected step_no 1, found 2" in e for e in errors)
