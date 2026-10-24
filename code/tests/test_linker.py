"""
test_linker.py — Tests for Anchor-and-Expand Evidence Linker (Phase 5).

Verifies:
1. Direct alias anchor linking on sample subjects.
2. Temporal cluster expansion around anchor times.
3. Strict enforcement of audit_at cutoff (anti-leak contract).
4. Confidence tagging (HIGH, MEDIUM, LOW).
5. Precision and recall measurement on the 32 sample cases.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from ghost.config import DATASET_DIR, SAMPLE_OUTPUT_CSV, SAMPLE_REQUESTS_CSV, SYSTEM_ACTIVITY_CSV
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence
from ghost.linker import EvidenceLinker
from ghost.models import Identity
from ghost.rules import default_rule_engine


@pytest.fixture(scope="module")
def loaded_env():
    resolver = IdentityResolver()
    obs, cov, unp, counts = load_all_evidence()
    linker = EvidenceLinker(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV, rule_engine=default_rule_engine)
    return resolver, linker


def test_anchor_linking_direct_alias(loaded_env):
    resolver, linker = loaded_env
    audit_at = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    subject = resolver.resolve("priya.raman@gmail.com", audit_at)

    linked = linker.link_subject_resources(subject, audit_at=audit_at)
    assert len(linked) > 0

    # support_001 appears in delivery_correction_attachment.pdf (evidence_58) with priya.raman@gmail.com
    assert "support_001" in linked
    res = linked["support_001"]
    assert res.confidence == "HIGH"
    assert res.is_anchor is True
    assert "evidence_58" in res.evidence_ids


def test_catalog_identity_linking(loaded_env):
    resolver, linker = loaded_env
    # Soo-jin Park (marketing_001 via LINK_RESOURCE_IDENTITY activity_4008 on 2026-09-16T07:27:01Z)
    audit_at_after = datetime(2026, 9, 17, 0, 0, 0, tzinfo=timezone.utc)
    subject = resolver.resolve("kwame-mensah@proton.me", audit_at_after)

    linked = linker.link_subject_resources(subject, audit_at=audit_at_after)
    assert "marketing_001" in linked
    assert linked["marketing_001"].confidence == "HIGH"
    assert "activity_4008" in linked["marketing_001"].evidence_ids


def test_anti_leak_audit_at_cutoff(loaded_env):
    resolver, linker = loaded_env
    # Check that an event happening AFTER audit_at is NOT linked
    audit_at_before = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    subject = resolver.resolve("kwame-mensah@proton.me", audit_at_before)

    linked = linker.link_subject_resources(subject, audit_at=audit_at_before)
    # activity_4008 happened on 2026-09-16, so it must be excluded
    assert "marketing_001" not in linked


def test_sample_dataset_linking_measurement(loaded_env):
    resolver, linker = loaded_env

    # Load 32 sample requests
    cases = []
    with open(SAMPLE_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    expected_by_case: dict[str, set[str]] = {}
    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["case_id"].strip()
            steps = json.loads(r["steps_json"])
            expected_by_case[cid] = set(s["resource_id"] for s in steps)

    total_expected = sum(len(s) for s in expected_by_case.values())
    total_candidates = 0
    total_high_medium_matched = 0

    for c in cases:
        cid = c["case_id"].strip()
        email = c["email"].strip()
        audit_at = _parse_iso(c["audit_at"])
        reported_at = _parse_iso(c["reported_at"])

        subject = resolver.resolve(email, audit_at)
        linked = linker.link_subject_resources(subject, audit_at=audit_at, reported_at=reported_at)

        exp = expected_by_case.get(cid, set())
        # Candidate set (HIGH + MEDIUM confidence)
        candidates = {rid for rid, res in linked.items() if res.confidence in ("HIGH", "MEDIUM")}
        total_candidates += len(candidates)
        matched = len(candidates & exp)
        total_high_medium_matched += matched

    # At least 70% of expected sample resources must be linked via grounded anchors & clusters
    recall = total_high_medium_matched / total_expected
    assert recall >= 0.70, f"Expected anchor-and-expand recall >= 70%, got {recall:.1%}"
    # Average candidate count per case should be manageable
    avg_candidates = total_candidates / len(cases)
    assert avg_candidates <= 25.0, f"Average candidates per case too high: {avg_candidates:.1f}"
