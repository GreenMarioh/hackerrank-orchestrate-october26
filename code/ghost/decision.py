"""Audit Decision Engine for Ghost Data Still Exists (Phase 8).

Composes:
- RequestIntentClassifier (code/ghost/intent.py)
- IdentityResolver (code/ghost/identity.py)
- EvidenceLinker (code/ghost/linker.py)
- RuleEngine (code/ghost/rules.py)
- StateEvaluator (code/ghost/state.py)
- FlowRiskDetector (code/ghost/flows.py)

Enforces:
1. Classification of request intent into COMPLETE, INCOMPLETE, or NOT_APPLICABLE.
2. For NOT_APPLICABLE: steps_json = [].
3. For COMPLETE: only verification steps proving required state at audit_at, citing valid evidence_id.
4. For INCOMPLETE: ordered FINDING -> REMEDIATION -> VERIFICATION steps.
5. Strict operation and dependency sorting:
   - Findings: REPORT_REMAINING_RECORD -> REPORT_EXPOSED_PII -> REPORT_ACTIVE_DATA_FLOW -> REPORT_RESTORE_RISK
   - Remediation: DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE_RECORD -> REDACT_RECORD -> ANONYMIZE_RECORD
   - Verification: VERIFY_RECORD_ABSENT -> VERIFY_RECORD_PRESENT -> VERIFY_RECORD_REDACTED -> VERIFY_RECORD_ANONYMIZED -> VERIFY_DATA_FLOW_DISABLED -> VERIFY_RESTORE_BLOCKED
6. 1-indexed consecutive step_no.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ghost.flows import FlowRiskDetector, FlowRiskFinding
from ghost.identity import IdentityResolver
from ghost.intent import IntentClassifier, RequestIntent
from ghost.linker import EvidenceLinker, LinkedResource
from ghost.models import Identity, Observation, SnapshotCoverage, Step
from ghost.rules import RuleEngine
from ghost.state import ResourceState, StateEvaluator


# Operation Priority Orders
FINDING_OP_ORDER = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
}

REMEDIATION_OP_ORDER = {
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
}

VERIFICATION_OP_ORDER = {
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}


@dataclass(frozen=True)
class CaseAuditResult:
    """End-to-end audit result for a single deletion request."""
    case_id: str
    deletion_status: str        # "COMPLETE" | "INCOMPLETE" | "NOT_APPLICABLE"
    steps: list[Step]
    subject_user_id: str | None
    intent_reason: str


class AuditDecisionEngine:
    """Orchestrates identity, evidence, state, flows, rules, and ordering into final case decisions."""

    def __init__(
        self,
        resolver: IdentityResolver,
        linker: EvidenceLinker,
        evaluator: StateEvaluator,
        flow_detector: FlowRiskDetector,
        rule_engine: RuleEngine,
        intent_classifier: IntentClassifier | None = None,
    ) -> None:
        self.resolver = resolver
        self.linker = linker
        self.evaluator = evaluator
        self.flow_detector = flow_detector
        self.rule_engine = rule_engine
        self.intent_classifier = intent_classifier or IntentClassifier()

    def audit_case(
        self,
        case_id: str,
        email: str,
        audit_at: datetime,
        reported_status: str | None = None,
        reported_at: datetime | None = None,
        request_text: str | None = None,
    ) -> CaseAuditResult:
        """Audits a single deletion request case and produces ordered steps according to the contract."""
        # 1. Determine request intent
        intent_res = self.intent_classifier.classify(request_text)
        if intent_res.intent == RequestIntent.NOT_APPLICABLE:
            return CaseAuditResult(
                case_id=case_id,
                deletion_status="NOT_APPLICABLE",
                steps=[],
                subject_user_id=None,
                intent_reason=intent_res.reason,
            )

        # 2. Resolve subject identity
        subject = self.resolver.resolve(email, audit_at)

        # 3. Link resources for subject <= audit_at
        linked = self.linker.link_subject_resources(
            subject, audit_at=audit_at, reported_at=reported_at
        )

        # 4. Evaluate state for each linked resource
        resource_states: dict[str, ResourceState] = {}
        for rid, lr in linked.items():
            resource_states[rid] = self.evaluator.determine_resource_state(lr, subject, audit_at)

        # 5. Detect flows and restore risks
        flow_findings = self.flow_detector.detect_all_flows_and_risks(subject, linked, audit_at)

        # 6. Determine whether deletion is COMPLETE or INCOMPLETE
        # Invariant: Only HIGH-confidence grounded resources with pre-cutoff evidence trigger remaining copy violations.
        has_violating_resource = any(
            not st.is_compliant and bool(st.evidence_id)
            for rid, st in resource_states.items()
            if linked[rid].confidence == "HIGH" and st.overall_state != "UNKNOWN"
        )
        has_active_flow_or_restore = any(ff.is_risk for ff in flow_findings)

        is_complete = not (has_violating_resource or has_active_flow_or_restore)

        # 7. Synthesize steps
        if is_complete:
            status = "COMPLETE"
            steps = self._assemble_complete_steps(resource_states, linked, flow_findings)
        else:
            status = "INCOMPLETE"
            steps = self._assemble_incomplete_steps(resource_states, linked, flow_findings)

        return CaseAuditResult(
            case_id=case_id,
            deletion_status=status,
            steps=steps,
            subject_user_id=subject.user_id,
            intent_reason=intent_res.reason,
        )

    def _assemble_complete_steps(
        self,
        resource_states: dict[str, ResourceState],
        linked: dict[str, LinkedResource],
        flow_findings: list[FlowRiskFinding],
    ) -> list[Step]:
        """Assemble verification steps for a COMPLETE case, citing valid pre-cutoff evidence."""
        verif_steps: list[Step] = []

        # 1. Resource verifications for compliant states that have valid evidence
        for rid, st in resource_states.items():
            lr = linked.get(rid)
            if not lr or lr.confidence != "HIGH":
                continue
            if not st.is_compliant or not st.evidence_id:
                continue

            if st.overall_state == "ABSENT":
                op = "VERIFY_RECORD_ABSENT"
                state = "ABSENT"
            elif st.overall_state in ("PRESENT_REDACTED", "REDACTED"):
                if st.category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD"):
                    op = "VERIFY_RECORD_PRESENT"
                    state = "PRESENT"
                else:
                    op = "VERIFY_RECORD_REDACTED"
                    state = "REDACTED"
            elif st.overall_state in ("PRESENT_ANONYMIZED", "ANONYMIZED"):
                op = "VERIFY_RECORD_ANONYMIZED"
                state = "ANONYMIZED"
            elif st.overall_state in ("PRESENT_IDENTIFIED", "PRESENT"):
                # Retained records (e.g. security audit log, legal hold)
                op = "VERIFY_RECORD_PRESENT"
                state = "PRESENT"
            else:
                continue

            verif_steps.append(
                Step(
                    step_no=0,
                    phase="VERIFICATION",
                    system_id=st.system_id,
                    resource_id=st.resource_id,
                    operation=op,
                    state=state,
                    evidence_id=st.evidence_id,
                )
            )

        # 2. Flow and restore verifications
        for ff in flow_findings:
            if not ff.is_risk and ff.evidence_id:
                if ff.risk_type == "ACTIVE_DATA_FLOW":
                    op = "VERIFY_DATA_FLOW_DISABLED"
                    st_val = "DISABLED"
                else:
                    op = "VERIFY_RESTORE_BLOCKED"
                    st_val = "BLOCKED"

                verif_steps.append(
                    Step(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=ff.system_id,
                        resource_id=ff.resource_id,
                        operation=op,
                        state=st_val,
                        evidence_id=ff.evidence_id,
                    )
                )

        # Sort verification steps by standard order
        sorted_verifs = self._sort_verification_steps(verif_steps)
        return self._renumber_steps(sorted_verifs)

    def _assemble_incomplete_steps(
        self,
        resource_states: dict[str, ResourceState],
        linked: dict[str, LinkedResource],
        flow_findings: list[FlowRiskFinding],
    ) -> list[Step]:
        """Assemble FINDING, REMEDIATION, and post-remediation VERIFICATION steps for an INCOMPLETE case."""
        finding_steps: list[Step] = []
        remediation_steps: list[Step] = []
        verification_steps: list[Step] = []

        # Track which resources are remediated
        remediated_rids: set[str] = set()

        # 1. Resource findings & remediations (HIGH confidence only)
        for rid, st in resource_states.items():
            lr = linked.get(rid)
            if not lr or lr.confidence != "HIGH":
                continue
            if st.is_compliant or st.overall_state == "UNKNOWN":
                continue
            if not st.evidence_id:
                continue

            # What finding operation applies?
            if st.overall_state == "PRESENT_IDENTIFIED":
                # Check category rule to see if record should be deleted, redacted, or anonymized
                if st.category in ("USER_PROFILE", "MARKETING_PROFILE", "SEARCH_INDEX_ENTRY", "SUPPORT_ATTACHMENT", "EXPORT_ARCHIVE"):
                    f_op = "REPORT_REMAINING_RECORD"
                    r_op = "DELETE_RECORD"
                    v_op = "VERIFY_RECORD_ABSENT"
                    r_state = "ABSENT"
                elif st.category in ("SUPPORT_CONVERSATION", "SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"):
                    f_op = "REPORT_EXPOSED_PII"
                    r_op = "REDACT_RECORD"
                    v_op = "VERIFY_RECORD_REDACTED"
                    r_state = "REDACTED"
                elif st.category in ("ANALYTICS_PROFILE", "ORDER_RECORD"):
                    f_op = "REPORT_EXPOSED_PII"
                    r_op = "ANONYMIZE_RECORD"
                    v_op = "VERIFY_RECORD_ANONYMIZED"
                    r_state = "ANONYMIZED"
                else:
                    f_op = "REPORT_REMAINING_RECORD"
                    r_op = "DELETE_RECORD"
                    v_op = "VERIFY_RECORD_ABSENT"
                    r_state = "ABSENT"

                finding_steps.append(
                    Step(
                        step_no=0,
                        phase="FINDING",
                        system_id=st.system_id,
                        resource_id=st.resource_id,
                        operation=f_op,
                        state="PRESENT",
                        evidence_id=st.evidence_id,
                    )
                )
                remediation_steps.append(
                    Step(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=st.system_id,
                        resource_id=st.resource_id,
                        operation=r_op,
                        state=r_state,
                        evidence_id="",
                    )
                )
                verification_steps.append(
                    Step(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=st.system_id,
                        resource_id=st.resource_id,
                        operation=v_op,
                        state=r_state,
                        evidence_id="",
                    )
                )
                remediated_rids.add(st.resource_id)

        # 2. Flow and restore findings & remediations
        f_flows, r_flows, v_flows = FlowRiskDetector.generate_flow_steps(
            flow_findings, is_complete=False
        )
        finding_steps.extend(f_flows)
        remediation_steps.extend(r_flows)
        verification_steps.extend(v_flows)
        for ff in flow_findings:
            if ff.is_risk:
                remediated_rids.add(ff.resource_id)

        # 3. Add baseline post-remediation verification checks for already-compliant or primary resources
        # (e.g. verifying primary account_service record is ABSENT, audit_record is PRESENT)
        for rid, st in resource_states.items():
            if rid in remediated_rids:
                continue
            lr = linked.get(rid)
            if not lr or lr.confidence != "HIGH":
                continue
            if not st.is_compliant:
                continue

            # Standard required post-remediation checks
            if st.overall_state == "ABSENT" and st.system_id == "account_service":
                verification_steps.append(
                    Step(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=st.system_id,
                        resource_id=st.resource_id,
                        operation="VERIFY_RECORD_ABSENT",
                        state="ABSENT",
                        evidence_id="",
                    )
                )
            elif st.overall_state in ("PRESENT", "PRESENT_IDENTIFIED", "PRESENT_REDACTED") and st.category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD"):
                verification_steps.append(
                    Step(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=st.system_id,
                        resource_id=st.resource_id,
                        operation="VERIFY_RECORD_PRESENT",
                        state="PRESENT",
                        evidence_id="",
                    )
                )

        # Sort each phase strictly according to AGENTS.md contract
        sorted_findings = self._sort_finding_steps(finding_steps)
        sorted_remediations = self._sort_remediation_steps(remediation_steps)
        sorted_verifications = self._sort_verification_steps(verification_steps)

        all_steps = sorted_findings + sorted_remediations + sorted_verifications
        return self._renumber_steps(all_steps)

    def _sort_finding_steps(self, steps: list[Step]) -> list[Step]:
        """Sort FINDING steps deterministically by operation priority, system, and resource."""
        return sorted(
            steps,
            key=lambda s: (
                FINDING_OP_ORDER.get(s.operation, 99),
                s.system_id,
                s.resource_id,
            ),
        )

    def _sort_remediation_steps(self, steps: list[Step]) -> list[Step]:
        """Sort REMEDIATION steps deterministically by dependency order:
        Flow/Restore disabled first -> Delete records -> Redact -> Anonymize.
        """
        return sorted(
            steps,
            key=lambda s: (
                REMEDIATION_OP_ORDER.get(s.operation, 99),
                s.system_id,
                s.resource_id,
            ),
        )

    def _sort_verification_steps(self, steps: list[Step]) -> list[Step]:
        """Sort VERIFICATION steps deterministically:
        Primary ABSENT -> Downstream ABSENT -> Retained PRESENT -> REDACTED -> ANONYMIZED -> FLOW_DISABLED -> RESTORE_BLOCKED.
        """
        return sorted(
            steps,
            key=lambda s: (
                VERIFICATION_OP_ORDER.get(s.operation, 99),
                0 if s.system_id == "account_service" else 1,
                s.system_id,
                s.resource_id,
            ),
        )

    def _renumber_steps(self, steps: list[Step]) -> list[Step]:
        """Assign consecutive 1-indexed step_no."""
        renumbered: list[Step] = []
        for i, s in enumerate(steps, start=1):
            renumbered.append(
                Step(
                    step_no=i,
                    phase=s.phase,
                    system_id=s.system_id,
                    resource_id=s.resource_id,
                    operation=s.operation,
                    state=s.state,
                    evidence_id=s.evidence_id,
                )
            )
        return renumbered
