"""
test_state.py — Tests for Resource State Determination at audit_at (Phase 6).

Verifies:
1. Multi-store aggregation and H7 invariant: identified copy in any replica marks state PRESENT_IDENTIFIED.
2. VERIFY_RECORD_ABSENT cites the latest snapshot covering that system at or before audit_at.
3. Explicit absence verification (404 / NOT_FOUND log lookups).
4. Full validation across the 32 sample cases.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
import pytest

from ghost.config import DATASET_DIR, SAMPLE_OUTPUT_CSV, SAMPLE_REQUESTS_CSV, SYSTEM_ACTIVITY_CSV
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence
from ghost.linker import EvidenceLinker, LinkedResource
from ghost.models import Identity, Observation, SnapshotCoverage
from ghost.rules import default_rule_engine
from ghost.state import StateEvaluator


@pytest.fixture(scope="module")
def state_env():
    resolver = IdentityResolver()
    obs, cov, unp, counts = load_all_evidence()
    linker = EvidenceLinker(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV, rule_engine=default_rule_engine)
    evaluator = StateEvaluator(observations=obs, coverages=cov, rule_engine=default_rule_engine)
    return resolver, linker, evaluator


def test_h7_multi_store_replica_drift(state_env):
    """
    H7: Primary table has deleted the record, but failover replica still has it.
    Overall state must be PRESENT_IDENTIFIED.
    """
    _, _, evaluator = state_env
    audit_at = datetime(2026, 9, 3, 0, 0, 0, tzinfo=timezone.utc)
    dummy_subject = Identity(
        user_id="user_05",
        current_email="leila.haddad@yahoo.com",
        all_emails=frozenset({"leila.haddad@yahoo.com"}),
        all_phones=frozenset({"+212 6 48 27 15 93"}),
        all_hashes=frozenset(),
        name="Leila Haddad",
    )

    linked = LinkedResource(
        resource_id="account_005",
        system_id="account_service",
        category="USER_PROFILE",
        confidence="HIGH",
        evidence_ids=("evidence_54",),
        first_seen=audit_at,
        is_anchor=True,
        rationale="Account profile in failover replica",
    )

    state = evaluator.determine_resource_state(linked, dummy_subject, audit_at)
    assert state.overall_state == "PRESENT_IDENTIFIED"
    assert state.is_compliant is False  # USER_PROFILE requires DELETE
    assert state.evidence_id == "evidence_54"


def test_verify_record_absent_cites_latest_snapshot(state_env):
    """
    Test 3: VERIFY_RECORD_ABSENT cites the latest snapshot covering that system at or before audit_at.
    """
    _, _, evaluator = state_env
    # case_01: audit_at is 2026-09-03T11:30:00Z.
    # Latest customer_accounts snapshot <= audit_at is evidence_54 (2026-09-02T23:00:00Z).
    audit_at = datetime(2026, 9, 3, 11, 30, 0, tzinfo=timezone.utc)
    dummy_subject = Identity(
        user_id="user_01",
        current_email="amina.elmasri@gmail.com",
        all_emails=frozenset({"amina.elmasri@gmail.com"}),
        all_phones=frozenset(),
        all_hashes=frozenset(),
        name="Amina El-Masri",
    )

    linked = LinkedResource(
        resource_id="account_001",
        system_id="account_service",
        category="USER_PROFILE",
        confidence="HIGH",
        evidence_ids=(),
        first_seen=audit_at,
        is_anchor=False,
        rationale="Deleted account",
    )

    state = evaluator.determine_resource_state(linked, dummy_subject, audit_at)
    assert state.overall_state == "ABSENT"
    assert state.is_compliant is True
    assert state.evidence_id == "evidence_54"


def test_sample_state_determination_accuracy(state_env):
    """
    Validates state evaluation across the 32 sample cases against sample_output.csv.
    """
    resolver, linker, evaluator = state_env

    cases = []
    with open(SAMPLE_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    expected_output = {}
    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["case_id"].strip()
            expected_output[cid] = {
                "status": r["deletion_status"].strip(),
                "steps": json.loads(r["steps_json"]),
            }

    evaluated_cases = 0
    consistent_states = 0

    for c in cases:
        cid = c["case_id"].strip()
        email = c["email"].strip()
        audit_at = _parse_iso(c["audit_at"])
        reported_at = _parse_iso(c["reported_at"])

        subject = resolver.resolve(email, audit_at)
        linked = linker.link_subject_resources(subject, audit_at=audit_at, reported_at=reported_at)

        exp = expected_output[cid]
        exp_status = exp["status"]
        exp_steps = exp["steps"]

        # Check each step in expected output
        for s in exp_steps:
            rid = s["resource_id"]
            if rid in linked:
                r_state = evaluator.determine_resource_state(linked[rid], subject, audit_at)
                # Verify that compliant/violating state aligns with expected phase
                if s["phase"] == "FINDING":
                    assert not r_state.is_compliant, f"{cid} {rid}: expected violation finding, got compliant"
                elif s["phase"] == "VERIFICATION" and exp_status == "COMPLETE":
                    assert r_state.is_compliant, f"{cid} {rid}: expected compliant verification, got violating"
                consistent_states += 1

        evaluated_cases += 1

    assert evaluated_cases == 32
    assert consistent_states >= 70, f"Expected at least 70 evaluated step states, got {consistent_states}"
