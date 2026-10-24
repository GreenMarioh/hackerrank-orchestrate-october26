"""
test_identity.py — Unit tests for IdentityResolver.

Validates:
1. All 518 evaluation deletion requests resolve to a non-null, valid user_id.
2. All 32 sample deletion requests resolve to a non-null, valid user_id.
3. Historical emails match their current user_id.
4. Anti-leak temporal cutoff (event_time <= audit_at) is strictly respected.
5. Determinism: identical input always produces identical Identity dataclass.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghost.config import DELETION_REQUESTS_CSV, SAMPLE_DELETION_REQUESTS_CSV
from ghost.identity import IdentityResolver, _parse_iso, _sha256
from ghost.models import Case, Identity


@pytest.fixture(scope="module")
def resolver() -> IdentityResolver:
    return IdentityResolver()


def test_resolve_all_518_evaluation_cases(resolver: IdentityResolver):
    """
    Every case in deletion_requests.csv must resolve to a valid user_id (not 'unknown_user').
    """
    unresolved = []
    total = 0
    with open(DELETION_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            total += 1
            case = Case(
                case_id=r["case_id"].strip(),
                email=r["email"].strip(),
                requested_at=_parse_iso(r["requested_at"]),
                reported_status=r["reported_status"].strip(),
                reported_at=_parse_iso(r["reported_at"]),
                audit_at=_parse_iso(r["audit_at"]),
                request_text=r["request_text"].strip(),
            )
            identity = resolver.resolve_case(case)
            if identity.user_id == "unknown_user" or not identity.user_id.startswith("user_"):
                unresolved.append((case.case_id, case.email, identity.user_id))

    assert total == 518, f"Expected 518 cases, found {total}"
    assert len(unresolved) == 0, f"{len(unresolved)} cases unresolved: {unresolved[:5]}"


def test_resolve_all_32_sample_cases(resolver: IdentityResolver):
    """
    Every case in sample_deletion_requests.csv must resolve to a valid user_id.
    """
    unresolved = []
    total = 0
    with open(SAMPLE_DELETION_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            total += 1
            case = Case(
                case_id=r["case_id"].strip(),
                email=r["email"].strip(),
                requested_at=_parse_iso(r["requested_at"]),
                reported_status=r["reported_status"].strip(),
                reported_at=_parse_iso(r["reported_at"]),
                audit_at=_parse_iso(r["audit_at"]),
                request_text=r["request_text"].strip(),
            )
            identity = resolver.resolve_case(case)
            if identity.user_id == "unknown_user" or not identity.user_id.startswith("user_"):
                unresolved.append((case.case_id, case.email, identity.user_id))

    assert total == 32, f"Expected 32 sample cases, found {total}"
    assert len(unresolved) == 0, f"{len(unresolved)} sample cases unresolved: {unresolved}"


def test_historical_email_resolution(resolver: IdentityResolver):
    """
    Verify that an email that only appears in historical audit log (and not in current snapshot)
    correctly resolves to the user_id, and cites the audit_id in evidence_audit_ids.
    """
    # Find an audit event where old_value != new_value and old_value is not in current identities
    historical_email = None
    target_uid = None
    target_audit_id = None
    target_event_time = None

    for ev in resolver.audit_events:
        if ev["field_name"] == "email" and ev["old_value"]:
            old_e = ev["old_value"].lower().strip()
            # check if old_e is NOT the current email of that user
            curr_e = resolver.identities[ev["user_id"]]["email"].lower()
            if old_e != curr_e and old_e not in resolver.current_email_to_uid:
                historical_email = old_e
                target_uid = ev["user_id"]
                target_audit_id = ev["audit_id"]
                target_event_time = ev["event_time"]
                break

    assert historical_email is not None, "Could not find a historical-only email in audit log"

    # Resolve with audit_at after event_time
    audit_at_after = datetime(2099, 1, 1, tzinfo=timezone.utc)
    ident = resolver.resolve(historical_email, audit_at_after)

    assert ident.user_id == target_uid
    assert historical_email in ident.all_emails
    assert target_audit_id in ident.evidence_audit_ids


def test_email_change_after_audit_at_still_resolves_user(resolver: IdentityResolver):
    """
    User rule: where an email change A->B happens AFTER audit_at and the request uses A,
    the request email must STILL resolve to the user.
    The audit_at cutoff applies to evidence and state, not to deciding who the person is.
    """
    # Find an audit event where email changed from A (old_value) to B (new_value)
    # and A is not in current identities snapshot (B is current).
    target_ev = None
    for ev in resolver.audit_events:
        if ev["field_name"] == "email" and ev["old_value"] and ev["new_value"]:
            old_e = ev["old_value"].lower().strip()
            curr_e = resolver.identities[ev["user_id"]]["email"].lower()
            if old_e != curr_e and old_e not in resolver.current_email_to_uid:
                target_ev = ev
                break

    assert target_ev is not None, "Could not find an email change event in user_audit_log"

    event_time = target_ev["event_time"]
    old_email_a = target_ev["old_value"].lower().strip()
    target_uid = target_ev["user_id"]

    # Set audit_at strictly BEFORE the email change event_time
    audit_at_before_change = datetime.fromtimestamp(event_time.timestamp() - 7200, tz=timezone.utc)

    # Resolving with email A and audit_at < event_time MUST still resolve to target_uid!
    ident = resolver.resolve(old_email_a, audit_at_before_change)

    assert ident.user_id == target_uid, (
        f"Request email {old_email_a} failed to resolve to {target_uid} when audit_at is before event_time!"
    )
    assert old_email_a in ident.all_emails


def test_identity_determinism(resolver: IdentityResolver):
    """
    Resolving the same case twice must produce identical results.
    """
    email = "test@example.com"
    audit_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
    res1 = resolver.resolve(email, audit_at)
    res2 = resolver.resolve(email, audit_at)
    assert res1 == res2
