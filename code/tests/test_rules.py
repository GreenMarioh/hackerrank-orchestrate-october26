"""
test_rules.py — Unit tests for Phase 4 Deletion Rules Engine.

Includes the 45 parameterized tests covering:
15 rules x (present-compliant, present-violating, absent/UNKNOWN) = 45 cases.
"""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from ghost.ingest.coordinator import load_all_evidence
from ghost.rules import RuleEngine, ConditionResult, default_rule_engine


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return default_rule_engine


def test_load_all_15_rules(engine: RuleEngine):
    assert len(engine.rules) == 15, f"Expected 15 rules, loaded {len(engine.rules)}"
    assert len(engine.rules_by_category) == 15


# ─────────────────────────────────────────────────────────────────────────────
# 45 Parameterized Test Cases: 15 rules x 3 states
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_CUTOFF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

CASES_45 = [
    # 1. USER_PROFILE
    ("USER_PROFILE", "present-violating", {"user_id": "u1", "email": "a@b.com"}, "MET", "DELETE"),
    ("USER_PROFILE", "present-compliant", {"user_id": "u1", "deleted": True}, "NOT_MET", "ABSENT"),
    ("USER_PROFILE", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 2. SECONDARY_IDENTIFIER
    ("SECONDARY_IDENTIFIER", "present-violating", {"user_id": "u1", "secondary_email": "s@b.com"}, "MET", "DELETE"),
    ("SECONDARY_IDENTIFIER", "present-compliant", {"deleted": True}, "NOT_MET", "ABSENT"),
    ("SECONDARY_IDENTIFIER", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 3. SEARCH_INDEX_ENTRY
    ("SEARCH_INDEX_ENTRY", "present-violating", {"resource_id": "search_1", "email": "a@b.com"}, "MET", "DELETE"),
    ("SEARCH_INDEX_ENTRY", "present-compliant", {"deleted": True}, "NOT_MET", "ABSENT"),
    ("SEARCH_INDEX_ENTRY", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 4. CACHE_ENTRY
    ("CACHE_ENTRY", "present-violating", {"cache_key": "user_1"}, "MET", "DELETE"),
    ("CACHE_ENTRY", "present-compliant", {"purged": True}, "NOT_MET", "ABSENT"),
    ("CACHE_ENTRY", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 5. SUPPORT_MESSAGE
    ("SUPPORT_MESSAGE", "present-compliant", {"ticket_id": "tick_1", "channel": "email"}, "MET", "REDACT"),
    ("SUPPORT_MESSAGE", "present-violating", {"shared": False, "agent": None}, "NOT_MET", "DELETE"),
    ("SUPPORT_MESSAGE", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 6. SUPPORT_ATTACHMENT
    ("SUPPORT_ATTACHMENT", "present-compliant", {"uploaded_by": "u1", "shared": False}, "MET", "DELETE"),
    ("SUPPORT_ATTACHMENT", "present-violating", {"shared": True}, "NOT_MET", "REDACT"),
    ("SUPPORT_ATTACHMENT", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 7. ANALYTICS_PROFILE
    ("ANALYTICS_PROFILE", "present-violating", {"user_id": "u1", "metrics": {"views": 5}}, "MET", "ANONYMIZE"),
    ("ANALYTICS_PROFILE", "present-compliant", {"user_id": None, "metrics": {"views": 5}}, "NOT_MET", "RETAIN"),
    ("ANALYTICS_PROFILE", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 8. PRODUCT_TELEMETRY
    ("PRODUCT_TELEMETRY", "present-violating", {"user_id": "u1", "events": 10}, "MET", "ANONYMIZE"),
    ("PRODUCT_TELEMETRY", "present-compliant", {"user_id": None, "events": 10}, "NOT_MET", "RETAIN"),
    ("PRODUCT_TELEMETRY", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 9. USER_EXPORT
    ("USER_EXPORT", "present-violating", {"file_name": "dump.csv", "download_available": True}, "MET", "DELETE"),
    ("USER_EXPORT", "present-compliant", {"deleted": True}, "NOT_MET", "ABSENT"),
    ("USER_EXPORT", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 10. MARKETING_PROFILE
    ("MARKETING_PROFILE", "present-violating", {"email": "m@b.com", "opt_in": True}, "MET", "DELETE"),
    ("MARKETING_PROFILE", "present-compliant", {"deleted": True}, "NOT_MET", "ABSENT"),
    ("MARKETING_PROFILE", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 11. EMAIL_DELIVERY_LOG
    ("EMAIL_DELIVERY_LOG", "present-compliant", {"email": "cust@b.com"}, "MET", "REDACT"),
    ("EMAIL_DELIVERY_LOG", "present-violating", {"status": "sent"}, "NOT_MET", "RETAIN"),
    ("EMAIL_DELIVERY_LOG", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 12. SECURITY_AUDIT_LOG
    ("SECURITY_AUDIT_LOG", "present-compliant", {"retention_until": "2027-01-01T00:00:00Z"}, "MET", "RETAIN"),
    ("SECURITY_AUDIT_LOG", "present-violating", {"retention_until": "2025-01-01T00:00:00Z"}, "NOT_MET", "DELETE"),
    ("SECURITY_AUDIT_LOG", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 13. LEGAL_HOLD_RECORD
    ("LEGAL_HOLD_RECORD", "present-compliant", {"retained_until": "2028-01-01T00:00:00Z", "retention_reason": "tax audit"}, "MET", "RETAIN"),
    ("LEGAL_HOLD_RECORD", "present-violating", {"active": False, "released": True}, "NOT_MET", "DELETE"),
    ("LEGAL_HOLD_RECORD", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 14. BACKUP_ARCHIVE
    ("BACKUP_ARCHIVE", "present-compliant", {"restore_allowed": False, "blockable": True}, "MET", "RETAIN"),
    ("BACKUP_ARCHIVE", "present-violating", {"blockable": False}, "NOT_MET", "DELETE"),
    ("BACKUP_ARCHIVE", "absent/UNKNOWN", {}, "UNKNOWN", None),

    # 15. ACCOUNT_TOMBSTONE
    ("ACCOUNT_TOMBSTONE", "present-violating", {"user_id": "u1", "email": "a@b.com"}, "MET", "REDACT"),
    ("ACCOUNT_TOMBSTONE", "present-compliant", {"user_id": "u1", "email": None, "name": None, "phone": None}, "NOT_MET", "RETAIN"),
    ("ACCOUNT_TOMBSTONE", "absent/UNKNOWN", {}, "UNKNOWN", None),
]


@pytest.mark.parametrize("category,state,fields,expected_status,expected_action", CASES_45)
def test_45_rule_evaluations(
    engine: RuleEngine,
    category: str,
    state: str,
    fields: dict,
    expected_status: str,
    expected_action: str | None,
):
    res = engine.evaluate_rule(category, fields=fields, audit_at=AUDIT_CUTOFF)
    assert res.status == expected_status, (
        f"{category} [{state}]: expected status {expected_status}, got {res.status} (reason: {res.reason})"
    )
    assert res.action == expected_action, (
        f"{category} [{state}]: expected action {expected_action}, got {res.action}"
    )


def test_zero_uncategorized_observations_in_dataset(engine: RuleEngine):
    all_observations, _, _, _ = load_all_evidence()
    uncategorized = []

    for obs in all_observations:
        cat, reason = engine.categorize_resource(
            resource_id=obs.resource_id,
            system_id=obs.system_id,
            fields=obs.fields,
            explicit_category=obs.category,
        )
        if not cat:
            uncategorized.append((obs.file_id, obs.system_id, obs.resource_id, reason))

    assert len(uncategorized) == 0, f"{len(uncategorized)} uncategorized observations found: {uncategorized[:5]}"
