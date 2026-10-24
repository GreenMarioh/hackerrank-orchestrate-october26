"""
test_flows.py — Comprehensive tests for Active Data Flow and Restore Risk Detection (Phase 7).

Verifies:
1. Active flow supported by pre-cutoff evidence.
2. A flow that became active only after audit_at is NOT reported active at audit_at.
3. Disabled / completed flow is NOT classified as active.
4. Flow with temporal proximity to a subject anchor but NO defensible link is excluded.
5. Restore risk with evidence connecting backup mechanism to identified subject data.
6. Backup existence alone without subject-specific link is excluded.
7. Conflicting store states: identified data in any store is treated as an active restore risk.
8. Missing, malformed, or ambiguous activity records handled gracefully.
9. Correct FINDING -> REMEDIATION -> VERIFICATION ordering.
10. Deterministic output across repeated runs.
11. End-to-end evaluation against sample dataset cases (case_09, case_11, case_14, case_15, case_17, case_18, case_20, case_26, case_27, case_28, case_29, case_30).
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
import pytest

from ghost.flows import FlowRiskDetector, FlowRiskFinding
from ghost.linker import LinkedResource
from ghost.models import Identity, Observation, Step


@pytest.fixture
def sample_subject():
    return Identity(
        user_id="user_99",
        name="Test Subject",
        current_email="test.subject@example.com",
        all_emails=frozenset({"test.subject@example.com", "alt.subject@example.com"}),
        all_phones=frozenset({"+1 555 0199"}),
        all_hashes=frozenset({"hash_user_99"}),
    )


def test_1_active_flow_pre_cutoff(sample_subject):
    """1. Active flow supported by pre-cutoff evidence."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    obs = [
        Observation(
            obs_id="obs_1",
            file_id="evidence_01",
            captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
            system_id="integration_service",
            store="log",
            resource_id="data_flow_100",
            category=None,
            fields={"email": "test.subject@example.com", "enabled": True, "status": "ACTIVE"},
            file_captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector = FlowRiskDetector(observations=obs)
    finding = detector.audit_resource("data_flow_100", "integration_service", sample_subject, audit_at)

    assert finding is not None
    assert finding.risk_type == "ACTIVE_DATA_FLOW"
    assert finding.state == "ACTIVE"
    assert finding.is_risk is True
    assert finding.evidence_id == "evidence_01"


def test_2_flow_active_only_after_audit_at(sample_subject):
    """2. A flow that became active only after audit_at must not be reported active at audit_at."""
    audit_at = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    # Observation captured AFTER audit_at
    obs = [
        Observation(
            obs_id="obs_future",
            file_id="evidence_future",
            captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
            system_id="integration_service",
            store="log",
            resource_id="data_flow_100",
            category=None,
            fields={"email": "test.subject@example.com", "enabled": True},
            file_captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector = FlowRiskDetector(observations=obs)
    # Should find no defensible link <= audit_at, returning None
    finding = detector.audit_resource("data_flow_100", "integration_service", sample_subject, audit_at)
    assert finding is None


def test_3_disabled_flow_not_active(sample_subject):
    """3. A disabled or completed flow must not be classified as active."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    obs = [
        Observation(
            obs_id="obs_disabled",
            file_id="evidence_02",
            captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
            system_id="integration_service",
            store="primary",
            resource_id="data_flow_200",
            category=None,
            fields={"user_id": "user_99", "enabled": False, "status": "DISABLED", "last_delivery_status": "stopped"},
            file_captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector = FlowRiskDetector(observations=obs)
    finding = detector.audit_resource("data_flow_200", "integration_service", sample_subject, audit_at)

    assert finding is not None
    assert finding.risk_type == "ACTIVE_DATA_FLOW"
    assert finding.state == "DISABLED"
    assert finding.is_risk is False
    assert finding.evidence_id == "evidence_02"


def test_4_temporal_proximity_without_subject_link_excluded(sample_subject):
    """4. A flow with temporal proximity to a subject anchor but no defensible link must be excluded."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    # Observation belongs to an unrelated user, despite being observed at the same time
    obs = [
        Observation(
            obs_id="obs_unrelated",
            file_id="evidence_01",
            captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
            system_id="integration_service",
            store="log",
            resource_id="data_flow_300",
            category=None,
            fields={"email": "stranger@other.com", "enabled": True},
            file_captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector = FlowRiskDetector(observations=obs)
    finding = detector.audit_resource("data_flow_300", "integration_service", sample_subject, audit_at)
    assert finding is None


def test_5_restore_risk_connected_to_subject(sample_subject):
    """5. Restore risk with evidence that connects the backup to identified subject data."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    obs = [
        Observation(
            obs_id="obs_backup",
            file_id="evidence_93",
            captured_at=datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc),
            system_id="backup_service",
            store="archive",
            resource_id="backup_400",
            category=None,
            fields={"customer_email": "test.subject@example.com", "restore_allowed": 1, "deletion_block": False},
            file_captured_at=datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector = FlowRiskDetector(observations=obs)
    finding = detector.audit_resource("backup_400", "backup_service", sample_subject, audit_at)

    assert finding is not None
    assert finding.risk_type == "RESTORE_RISK"
    assert finding.state == "ACTIVE"
    assert finding.is_risk is True
    assert finding.evidence_id == "evidence_93"


def test_6_backup_existence_alone_insufficient(sample_subject):
    """6. A backup record whose existence alone is insufficient to establish subject link is excluded."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    obs = [
        Observation(
            obs_id="obs_system_backup",
            file_id="evidence_93",
            captured_at=datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc),
            system_id="backup_service",
            store="archive",
            resource_id="backup_system_weekly",
            category=None,
            fields={"type": "system_catalog", "restore_allowed": True},
            file_captured_at=datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector = FlowRiskDetector(observations=obs)
    finding = detector.audit_resource("backup_system_weekly", "backup_service", sample_subject, audit_at)
    assert finding is None


def test_7_conflicting_backup_states_multi_store(sample_subject):
    """7. Replica or backup with conflicting store states: identified unblocked copy marks ACTIVE risk."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    # Log trace shows blocked, but snapshot store shows restore allowed
    obs = [
        Observation(
            obs_id="obs_b1",
            file_id="evidence_06",
            captured_at=datetime(2026, 9, 14, 8, 0, 0, tzinfo=timezone.utc),
            system_id="backup_service",
            store="log",
            resource_id="backup_500",
            category=None,
            fields={"user_id": "user_99", "restore_allowed": False},
            file_captured_at=datetime(2026, 9, 14, 8, 0, 0, tzinfo=timezone.utc),
        ),
        Observation(
            obs_id="obs_b2",
            file_id="evidence_93",
            captured_at=datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc),
            system_id="backup_service",
            store="archive",
            resource_id="backup_500",
            category=None,
            fields={"user_id": "user_99", "restore_allowed": True},
            file_captured_at=datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc),
        ),
    ]
    detector = FlowRiskDetector(observations=obs)
    finding = detector.audit_resource("backup_500", "backup_service", sample_subject, audit_at)

    assert finding is not None
    assert finding.state == "ACTIVE"
    assert finding.is_risk is True
    # Cites latest evidence establishing the state
    assert finding.evidence_id == "evidence_93"


def test_8_malformed_activity_records(sample_subject):
    """8. Missing, malformed, or ambiguous activity records are handled gracefully."""
    detector = FlowRiskDetector(observations=[])
    # Empty or missing resource
    finding = detector.audit_resource("non_existent_flow", "integration_service", sample_subject, datetime.now(timezone.utc))
    assert finding is None


def test_9_step_generation_and_ordering():
    """9. Correct finding/remediation/verification ordering."""
    findings = [
        FlowRiskFinding(
            resource_id="data_flow_100",
            system_id="integration_service",
            risk_type="ACTIVE_DATA_FLOW",
            state="ACTIVE",
            is_risk=True,
            evidence_id="evidence_01",
            details="Active data flow",
        ),
        FlowRiskFinding(
            resource_id="backup_200",
            system_id="backup_service",
            risk_type="RESTORE_RISK",
            state="ACTIVE",
            is_risk=True,
            evidence_id="evidence_02",
            details="Active restore risk",
        ),
    ]

    f_steps, r_steps, v_steps = FlowRiskDetector.generate_flow_steps(findings, is_complete=False)

    # 1. Findings
    assert len(f_steps) == 2
    assert f_steps[0].operation == "REPORT_ACTIVE_DATA_FLOW"
    assert f_steps[0].state == "ACTIVE"
    assert f_steps[0].evidence_id == "evidence_01"
    assert f_steps[1].operation == "REPORT_RESTORE_RISK"
    assert f_steps[1].state == "ACTIVE"
    assert f_steps[1].evidence_id == "evidence_02"

    # 2. Remediation (DISABLE_DATA_FLOW before BLOCK_RESTORE)
    assert len(r_steps) == 2
    assert r_steps[0].operation == "DISABLE_DATA_FLOW"
    assert r_steps[0].state == "DISABLED"
    assert r_steps[0].evidence_id == ""
    assert r_steps[1].operation == "BLOCK_RESTORE"
    assert r_steps[1].state == "BLOCKED"
    assert r_steps[1].evidence_id == ""

    # 3. Post-remediation verification
    assert len(v_steps) == 2
    assert v_steps[0].operation == "VERIFY_DATA_FLOW_DISABLED"
    assert v_steps[0].state == "DISABLED"
    assert v_steps[0].evidence_id == ""
    assert v_steps[1].operation == "VERIFY_RESTORE_BLOCKED"
    assert v_steps[1].state == "BLOCKED"
    assert v_steps[1].evidence_id == ""


def test_10_deterministic_output(sample_subject):
    """10. Deterministic output across repeated runs."""
    audit_at = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    obs = [
        Observation(
            obs_id="obs_1",
            file_id="evidence_01",
            captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
            system_id="integration_service",
            store="log",
            resource_id="data_flow_100",
            category=None,
            fields={"email": "test.subject@example.com", "enabled": True},
            file_captured_at=datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
    ]
    detector1 = FlowRiskDetector(observations=obs)
    detector2 = FlowRiskDetector(observations=obs)

    res1 = detector1.audit_resource("data_flow_100", "integration_service", sample_subject, audit_at)
    res2 = detector2.audit_resource("data_flow_100", "integration_service", sample_subject, audit_at)

    assert res1 == res2
    assert res1.state == res2.state
    assert res1.evidence_id == res2.evidence_id


def test_11_sample_dataset_flow_restore_verification():
    """
    11. End-to-end evaluation of FlowRiskDetector across all sample cases in sample_output.csv.
    """
    from ghost.config import SAMPLE_OUTPUT_CSV, SAMPLE_REQUESTS_CSV, SYSTEM_ACTIVITY_CSV
    from ghost.identity import IdentityResolver, _parse_iso
    from ghost.ingest.coordinator import load_all_evidence
    from ghost.linker import EvidenceLinker
    from ghost.rules import default_rule_engine

    resolver = IdentityResolver()
    obs, cov, unp, _ = load_all_evidence()
    linker = EvidenceLinker(obs, SYSTEM_ACTIVITY_CSV, default_rule_engine)
    detector = FlowRiskDetector(obs, SYSTEM_ACTIVITY_CSV)

    with open(SAMPLE_REQUESTS_CSV, encoding="utf-8") as f:
        cases = {r["case_id"]: r for r in csv.DictReader(f)}

    with open(SAMPLE_OUTPUT_CSV, encoding="utf-8") as f:
        expected = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

    # Target cases with flow or restore steps
    target_cases = [
        "case_09", "case_11", "case_14", "case_15", "case_17",
        "case_18", "case_20", "case_26", "case_27", "case_28",
        "case_29", "case_30"
    ]

    for cid in target_cases:
        c = cases[cid]
        audit_at = _parse_iso(c["audit_at"])
        reported_at = _parse_iso(c["reported_at"])
        exp_status, exp_steps = expected[cid]
        exp_flow_steps = [s for s in exp_steps if "DATA_FLOW" in s["operation"] or "RESTORE" in s["operation"]]

        subj = resolver.resolve(c["email"], audit_at)
        linked = linker.link_subject_resources(subj, audit_at, reported_at)

        findings = detector.detect_all_flows_and_risks(subj, linked, audit_at)
        f_steps, r_steps, v_steps = detector.generate_flow_steps(findings, is_complete=(exp_status == "COMPLETE"))

        # Check that expected findings match
        exp_finding_rids = {s["resource_id"]: s for s in exp_flow_steps if s["phase"] == "FINDING"}
        gen_finding_rids = {s.resource_id: s for s in f_steps}

        assert set(gen_finding_rids.keys()) == set(exp_finding_rids.keys()), f"Mismatch in {cid} findings"
        for rid, gen_step in gen_finding_rids.items():
            exp_step = exp_finding_rids[rid]
            assert gen_step.operation == exp_step["operation"], f"{cid} {rid} op mismatch"
            assert gen_step.state == exp_step["state"], f"{cid} {rid} state mismatch"
            assert gen_step.evidence_id == exp_step["evidence_id"], f"{cid} {rid} citation mismatch"

        if exp_status == "COMPLETE":
            exp_v_rids = {s["resource_id"]: s for s in exp_flow_steps if s["phase"] == "VERIFICATION"}
            gen_v_rids = {s.resource_id: s for s in v_steps}
            assert set(gen_v_rids.keys()) == set(exp_v_rids.keys()), f"Mismatch in {cid} verifications"
            for rid, gen_step in gen_v_rids.items():
                exp_step = exp_v_rids[rid]
                assert gen_step.operation == exp_step["operation"], f"{cid} {rid} v_op mismatch"
                assert gen_step.state == exp_step["state"], f"{cid} {rid} v_state mismatch"
                assert gen_step.evidence_id == exp_step["evidence_id"], f"{cid} {rid} v_citation mismatch"
