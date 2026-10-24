"""
test_rules_synthetic.py — Synthetic end-to-end tests for policy categories
that do not appear in the 32 sample cases:
1. CACHE_ENTRY
2. MARKETING_PROFILE
3. EMAIL_DELIVERY_LOG
4. SUPPORT_ATTACHMENT
5. LEGAL_HOLD_RECORD
6. SECONDARY_IDENTIFIER
7. PRODUCT_TELEMETRY
"""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from ghost.rules import RuleEngine, default_rule_engine


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return default_rule_engine


AUDIT_CUTOFF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_synthetic_cache_entry(engine: RuleEngine):
    # Active cache entry -> DELETE
    res = engine.evaluate_rule("CACHE_ENTRY", fields={"cache_key": "user:123", "value": "data"})
    assert res.status == "MET"
    assert res.action == "DELETE"

    # Purged cache entry -> ABSENT
    res_purged = engine.evaluate_rule("CACHE_ENTRY", fields={"purged": True})
    assert res_purged.status == "NOT_MET"
    assert res_purged.action == "ABSENT"


def test_synthetic_marketing_profile(engine: RuleEngine):
    # Active marketing opt-in -> DELETE
    res = engine.evaluate_rule("MARKETING_PROFILE", fields={"email": "promo@example.com", "opt_in": True})
    assert res.status == "MET"
    assert res.action == "DELETE"


def test_synthetic_email_delivery_log(engine: RuleEngine):
    # Log contains user email -> REDACT
    res_pii = engine.evaluate_rule("EMAIL_DELIVERY_LOG", fields={"email": "user@example.com", "msg_id": "m-1"})
    assert res_pii.status == "MET"
    assert res_pii.action == "REDACT"

    # Log with redacted email -> RETAIN
    res_redacted = engine.evaluate_rule("EMAIL_DELIVERY_LOG", fields={"email": None, "msg_id": "m-1"})
    assert res_redacted.status == "NOT_MET"
    assert res_redacted.action == "RETAIN"


def test_synthetic_support_attachment(engine: RuleEngine):
    # Attachment belonging only to subject -> DELETE
    res_solo = engine.evaluate_rule("SUPPORT_ATTACHMENT", fields={"uploaded_by": "user_10", "shared": False})
    assert res_solo.status == "MET"
    assert res_solo.action == "DELETE"

    # Shared attachment with another user -> REDACT
    res_shared = engine.evaluate_rule("SUPPORT_ATTACHMENT", fields={"uploaded_by": "user_10", "shared": True})
    assert res_shared.status == "NOT_MET"
    assert res_shared.action == "REDACT"


def test_synthetic_legal_hold_record(engine: RuleEngine):
    # Active legal hold within retention window -> RETAIN
    res_active = engine.evaluate_rule(
        "LEGAL_HOLD_RECORD",
        fields={"retained_until": "2033-12-31T23:59:59Z", "retention_reason": "tax_audit"},
        audit_at=AUDIT_CUTOFF,
    )
    assert res_active.status == "MET"
    assert res_active.action == "RETAIN"

    # Released legal hold -> DELETE
    res_released = engine.evaluate_rule(
        "LEGAL_HOLD_RECORD",
        fields={"active": False, "released": True},
        audit_at=AUDIT_CUTOFF,
    )
    assert res_released.status == "NOT_MET"
    assert res_released.action == "DELETE"


def test_synthetic_secondary_identifier(engine: RuleEngine):
    # Secondary identifier record present -> DELETE
    res = engine.evaluate_rule("SECONDARY_IDENTIFIER", fields={"user_id": "user_10", "alias": "alias@example.com"})
    assert res.status == "MET"
    assert res.action == "DELETE"


def test_synthetic_product_telemetry(engine: RuleEngine):
    # Attributable telemetry with user_id -> ANONYMIZE
    res_attr = engine.evaluate_rule("PRODUCT_TELEMETRY", fields={"user_id": "user_10", "click_count": 42})
    assert res_attr.status == "MET"
    assert res_attr.action == "ANONYMIZE"

    # Unlinked telemetry without user identifiers -> RETAIN
    res_unlinked = engine.evaluate_rule("PRODUCT_TELEMETRY", fields={"user_id": None, "click_count": 42})
    assert res_unlinked.status == "NOT_MET"
    assert res_unlinked.action == "RETAIN"
