"""Unit and behavioral tests for AuditDecisionEngine (code/ghost/decision.py).

Tests:
1. NOT_APPLICABLE request yields deletion_status="NOT_APPLICABLE" and steps=[].
2. COMPLETE case yields only VERIFICATION phase steps with non-empty evidence_id.
3. INCOMPLETE case yields strictly ordered FINDING -> REMEDIATION -> VERIFICATION phases.
4. INCOMPLETE case remediation and future verification steps have evidence_id="".
5. Consecutive 1-indexed step_no (starts at 1, step[i].step_no == i+1).
6. Operation priority within phases:
   - Remediation: DISABLE_DATA_FLOW before DELETE_RECORD before REDACT_RECORD
   - Verification: ABSENT before PRESENT before REDACTED before FLOW_DISABLED
7. Retained records (SECURITY_AUDIT_LOG) are verified as PRESENT.
"""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from ghost.decision import AuditDecisionEngine, CaseAuditResult
from ghost.flows import FlowRiskFinding
from ghost.intent import IntentClassifier, IntentClassificationResult, RequestIntent
from ghost.linker import LinkedResource
from ghost.models import Identity, Observation, SnapshotCoverage, Step
from ghost.rules import default_rule_engine
from ghost.state import ResourceState, StateEvaluator


class MockIntentClassifier:
    def __init__(self, intent: RequestIntent, reason: str = "mock"):
        self._intent = intent
        self._reason = reason

    def classify(self, text: str | None) -> IntentClassificationResult:
        return IntentClassificationResult(intent=self._intent, reason=self._reason, confidence=1.0)


class MockResolver:
    def __init__(self, identity: Identity):
        self._id = identity

    def resolve(self, email: str, audit_at: datetime) -> Identity:
        return self._id


class MockLinker:
    def __init__(self, linked: dict[str, LinkedResource]):
        self._linked = linked

    def link_subject_resources(self, subject: Identity, audit_at: datetime, reported_at: datetime | None = None) -> dict[str, LinkedResource]:
        return self._linked


class MockEvaluator:
    def __init__(self, states: dict[str, ResourceState]):
        self._states = states

    def determine_resource_state(self, lr: LinkedResource, subject: Identity, audit_at: datetime) -> ResourceState:
        return self._states[lr.resource_id]


class MockFlowDetector:
    def __init__(self, findings: list[FlowRiskFinding]):
        self._findings = findings

    def detect_all_flows_and_risks(self, subject: Identity, linked: dict[str, LinkedResource], audit_at: datetime) -> list[FlowRiskFinding]:
        return self._findings


@pytest.fixture
def base_identity() -> Identity:
    return Identity(
        user_id="user_99",
        current_email="test@example.com",
        all_emails=frozenset({"test@example.com"}),
        all_phones=frozenset({"+1234567890"}),
        all_hashes=frozenset({"hash99"}),
        name="Test User",
    )


def test_not_applicable_request(base_identity: Identity) -> None:
    intent_classifier = MockIntentClassifier(RequestIntent.NOT_APPLICABLE, "Marketing opt-out")
    engine = AuditDecisionEngine(
        resolver=MockResolver(base_identity),
        linker=MockLinker({}),
        evaluator=MockEvaluator({}),
        flow_detector=MockFlowDetector([]),
        rule_engine=default_rule_engine,
        intent_classifier=intent_classifier,
    )

    res = engine.audit_case(
        case_id="case_test_na",
        email="test@example.com",
        audit_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        request_text="Unsubscribe me from your newsletter.",
    )

    assert res.deletion_status == "NOT_APPLICABLE"
    assert res.steps == []
    assert res.intent_reason == "Marketing opt-out"


def test_complete_case_steps_and_citations(base_identity: Identity) -> None:
    intent_classifier = MockIntentClassifier(RequestIntent.DELETION_AUTHORIZED, "Delete account")
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)

    linked = {
        "account_100": LinkedResource(
            resource_id="account_100",
            system_id="account_service",
            category="USER_PROFILE",
            confidence="HIGH",
            evidence_ids=("evidence_54",),
            first_seen=now,
            is_anchor=True,
            rationale="anchor",
        ),
        "audit_100": LinkedResource(
            resource_id="audit_100",
            system_id="security_service",
            category="SECURITY_AUDIT_LOG",
            confidence="HIGH",
            evidence_ids=("evidence_54",),
            first_seen=now,
            is_anchor=True,
            rationale="anchor",
        ),
    }

    states = {
        "account_100": ResourceState(
            resource_id="account_100",
            system_id="account_service",
            category="USER_PROFILE",
            overall_state="ABSENT",
            is_compliant=True,
            evidence_id="evidence_54",
            store_states=(),
            rationale="proven absent",
        ),
        "audit_100": ResourceState(
            resource_id="audit_100",
            system_id="security_service",
            category="SECURITY_AUDIT_LOG",
            overall_state="PRESENT_REDACTED",
            is_compliant=True,
            evidence_id="evidence_54",
            store_states=(),
            rationale="retained log",
        ),
    }

    engine = AuditDecisionEngine(
        resolver=MockResolver(base_identity),
        linker=MockLinker(linked),
        evaluator=MockEvaluator(states),
        flow_detector=MockFlowDetector([]),
        rule_engine=default_rule_engine,
        intent_classifier=intent_classifier,
    )

    res = engine.audit_case(
        case_id="case_test_complete",
        email="test@example.com",
        audit_at=now,
        request_text="Delete my account permanently.",
    )

    assert res.deletion_status == "COMPLETE"
    assert len(res.steps) == 2
    for s in res.steps:
        assert s.phase == "VERIFICATION"
        assert s.evidence_id == "evidence_54"

    # Step order: account_service ABSENT before security_service PRESENT
    assert res.steps[0].step_no == 1
    assert res.steps[0].operation == "VERIFY_RECORD_ABSENT"
    assert res.steps[0].resource_id == "account_100"

    assert res.steps[1].step_no == 2
    assert res.steps[1].operation == "VERIFY_RECORD_PRESENT"
    assert res.steps[1].resource_id == "audit_100"


def test_incomplete_case_phase_order_and_evidence_citations(base_identity: Identity) -> None:
    intent_classifier = MockIntentClassifier(RequestIntent.DELETION_AUTHORIZED, "Delete account")
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)

    linked = {
        "account_200": LinkedResource(
            resource_id="account_200",
            system_id="account_service",
            category="USER_PROFILE",
            confidence="HIGH",
            evidence_ids=("evidence_54",),
            first_seen=now,
            is_anchor=True,
            rationale="anchor",
        ),
        "search_200": LinkedResource(
            resource_id="search_200",
            system_id="search_service",
            category="SEARCH_INDEX_ENTRY",
            confidence="HIGH",
            evidence_ids=("evidence_57",),
            first_seen=now,
            is_anchor=True,
            rationale="anchor",
        ),
    }

    # account_200 is compliant (ABSENT), search_200 is non-compliant (PRESENT_IDENTIFIED)
    states = {
        "account_200": ResourceState(
            resource_id="account_200",
            system_id="account_service",
            category="USER_PROFILE",
            overall_state="ABSENT",
            is_compliant=True,
            evidence_id="evidence_54",
            store_states=(),
            rationale="absent",
        ),
        "search_200": ResourceState(
            resource_id="search_200",
            system_id="search_service",
            category="SEARCH_INDEX_ENTRY",
            overall_state="PRESENT_IDENTIFIED",
            is_compliant=False,
            evidence_id="evidence_57",
            store_states=(),
            rationale="remaining index entry",
        ),
    }

    flow_finding = FlowRiskFinding(
        resource_id="flow_200",
        system_id="integration_service",
        risk_type="ACTIVE_DATA_FLOW",
        state="ACTIVE",
        is_risk=True,
        evidence_id="evidence_57",
        details="active sync",
    )

    engine = AuditDecisionEngine(
        resolver=MockResolver(base_identity),
        linker=MockLinker(linked),
        evaluator=MockEvaluator(states),
        flow_detector=MockFlowDetector([flow_finding]),
        rule_engine=default_rule_engine,
        intent_classifier=intent_classifier,
    )

    res = engine.audit_case(
        case_id="case_test_incomplete",
        email="test@example.com",
        audit_at=now,
        request_text="Delete my data.",
    )

    assert res.deletion_status == "INCOMPLETE"

    # Verify phase ordering: FINDING -> REMEDIATION -> VERIFICATION
    phases = [s.phase for s in res.steps]
    assert phases.count("FINDING") > 0
    assert phases.count("REMEDIATION") > 0
    assert phases.count("VERIFICATION") > 0

    first_rem = phases.index("REMEDIATION")
    first_ver = phases.index("VERIFICATION")
    assert all(p == "FINDING" for p in phases[:first_rem])
    assert all(p == "REMEDIATION" for p in phases[first_rem:first_ver])
    assert all(p == "VERIFICATION" for p in phases[first_ver:])

    # Verify step numbering: 1-indexed consecutive
    for idx, s in enumerate(res.steps, start=1):
        assert s.step_no == idx

    # Verify future remediation and post-remediation verification have empty evidence_id
    for s in res.steps:
        if s.phase in ("REMEDIATION", "VERIFICATION"):
            assert s.evidence_id == ""
        elif s.phase == "FINDING":
            assert s.evidence_id != ""

    # Verify remediation dependency ordering: flow disabled before record deletion
    rem_ops = [s.operation for s in res.steps if s.phase == "REMEDIATION"]
    assert rem_ops.index("DISABLE_DATA_FLOW") < rem_ops.index("DELETE_RECORD")


def test_comprehensive_verification_operation_order(base_identity: Identity) -> None:
    intent_classifier = MockIntentClassifier(RequestIntent.DELETION_AUTHORIZED, "Delete account")
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)

    # All compliant resources across all categories
    linked = {
        "account_primary": LinkedResource("account_primary", "account_service", "USER_PROFILE", "HIGH", ("evidence_92",), now, True, "anchor"),
        "audit_sec": LinkedResource("audit_sec", "security_service", "SECURITY_AUDIT_LOG", "HIGH", ("evidence_92",), now, True, "anchor"),
        "support_chat": LinkedResource("support_chat", "support_platform", "SUPPORT_CONVERSATION", "HIGH", ("evidence_92",), now, True, "anchor"),
        "analytics_prof": LinkedResource("analytics_prof", "analytics_platform", "ANALYTICS_PROFILE", "HIGH", ("evidence_92",), now, True, "anchor"),
    }

    states = {
        "account_primary": ResourceState("account_primary", "account_service", "USER_PROFILE", "ABSENT", True, "evidence_92", (), "absent"),
        "audit_sec": ResourceState("audit_sec", "security_service", "SECURITY_AUDIT_LOG", "PRESENT_REDACTED", True, "evidence_92", (), "retained"),
        "support_chat": ResourceState("support_chat", "support_platform", "SUPPORT_CONVERSATION", "PRESENT_REDACTED", True, "evidence_92", (), "redacted"),
        "analytics_prof": ResourceState("analytics_prof", "analytics_platform", "ANALYTICS_PROFILE", "PRESENT_ANONYMIZED", True, "evidence_92", (), "anonymized"),
    }

    flows = [
        FlowRiskFinding("flow_sync", "integration_service", "ACTIVE_DATA_FLOW", "DISABLED", False, "evidence_92", "disabled"),
        FlowRiskFinding("backup_archive", "backup_service", "RESTORE_RISK", "BLOCKED", False, "evidence_92", "blocked"),
    ]

    engine = AuditDecisionEngine(
        resolver=MockResolver(base_identity),
        linker=MockLinker(linked),
        evaluator=MockEvaluator(states),
        flow_detector=MockFlowDetector(flows),
        rule_engine=default_rule_engine,
        intent_classifier=intent_classifier,
    )

    res = engine.audit_case("case_all_verif", "test@example.com", now, request_text="Check complete deletion")
    assert res.deletion_status == "COMPLETE"
    assert len(res.steps) == 6

    ops = [s.operation for s in res.steps]
    expected_order = [
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    ]
    assert ops == expected_order

