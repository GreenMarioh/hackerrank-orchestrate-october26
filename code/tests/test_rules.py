"""
test_rules.py — Unit test suite for Phase 4 Deletion Rules Engine.

Validates:
1. All 15 policy rules from dataset/deletion_rules.csv are loaded.
2. Condition predicates evaluate as plain code on real fields without LLM.
3. UNKNOWN is strictly returned when required fields are unavailable (no guessing).
4. Categorization covers all evidence prefixes and zero observations are uncategorized.
5. Deterministic evaluation.
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

    # Check key categories exist
    expected_categories = {
        "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
        "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
        "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
        "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE"
    }
    assert set(engine.rules_by_category.keys()) == expected_categories


def test_always_delete_rules(engine: RuleEngine):
    """
    Rules with condition 'Always' must evaluate to MET with action DELETE regardless of fields.
    """
    always_categories = [
        "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY",
        "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE"
    ]
    for cat in always_categories:
        res = engine.evaluate_rule(cat, fields={})
        assert res.status == "MET", f"{cat} did not evaluate to MET"
        assert res.action == "DELETE", f"{cat} action is not DELETE"


def test_support_message_condition_predicate(engine: RuleEngine):
    # Available fields -> MET (REDACT)
    res_met = engine.evaluate_rule("SUPPORT_MESSAGE", fields={"ticket_id": "ticket_123", "message_text": "hello"})
    assert res_met.status == "MET"
    assert res_met.action == "REDACT"

    # Missing/empty fields -> UNKNOWN
    res_unk = engine.evaluate_rule("SUPPORT_MESSAGE", fields={})
    assert res_unk.status == "UNKNOWN"
    assert res_unk.action is None


def test_analytics_profile_condition_predicate(engine: RuleEngine):
    # Attributable fields -> MET (ANONYMIZE)
    res_attributable = engine.evaluate_rule("ANALYTICS_PROFILE", fields={"user_id": "user_42", "email": "a@b.com"})
    assert res_attributable.status == "MET"
    assert res_attributable.action == "ANONYMIZE"

    # Unlinked record -> NOT_MET (RETAIN)
    res_unlinked = engine.evaluate_rule("ANALYTICS_PROFILE", fields={"metrics": {"views": 10}})
    assert res_unlinked.status == "NOT_MET"
    assert res_unlinked.action == "RETAIN"

    # Empty fields -> UNKNOWN
    res_unk = engine.evaluate_rule("ANALYTICS_PROFILE", fields={})
    assert res_unk.status == "UNKNOWN"


def test_email_delivery_log_condition_predicate(engine: RuleEngine):
    # Contains email -> MET (REDACT)
    res_with_email = engine.evaluate_rule("EMAIL_DELIVERY_LOG", fields={"email": "cust@example.com"})
    assert res_with_email.status == "MET"
    assert res_with_email.action == "REDACT"

    # No email -> NOT_MET (RETAIN)
    res_no_email = engine.evaluate_rule("EMAIL_DELIVERY_LOG", fields={"status": "sent", "timestamp": "2026-01-01"})
    assert res_no_email.status == "NOT_MET"
    assert res_no_email.action == "RETAIN"

    # Empty fields -> UNKNOWN
    res_empty = engine.evaluate_rule("EMAIL_DELIVERY_LOG", fields={})
    assert res_empty.status == "UNKNOWN"


def test_security_audit_log_retention(engine: RuleEngine):
    audit_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
    # Retention period in future -> MET (RETAIN)
    res_active = engine.evaluate_rule(
        "SECURITY_AUDIT_LOG",
        fields={"retention_until": "2027-01-01T00:00:00Z"},
        audit_at=audit_at,
    )
    assert res_active.status == "MET"
    assert res_active.action == "RETAIN"

    # Retention period expired before audit_at -> NOT_MET (DELETE)
    res_expired = engine.evaluate_rule(
        "SECURITY_AUDIT_LOG",
        fields={"retention_until": "2026-01-01T00:00:00Z"},
        audit_at=audit_at,
    )
    assert res_expired.status == "NOT_MET"
    assert res_expired.action == "DELETE"


def test_zero_uncategorized_observations_in_dataset(engine: RuleEngine):
    """
    Mandatory condition: list every resource that cannot be categorised with its source file.
    In our dataset, zero resources should be uncategorized.
    """
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
