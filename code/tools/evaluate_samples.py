"""
evaluate_samples.py — Comprehensive evaluation and diagnostic tool for development.

Evaluates:
1. Resource linking precision, recall, F1 across the 32 samples.
2. Unlinked expected steps investigation.
3. State determination accuracy on linked steps (Findings and Verifications).
4. Citation correctness and temporal anti-leak validation.
5. Multi-store aggregation and H7 replica drift detection.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sys

# Ensure code root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from ghost.config import (
    DATASET_DIR,
    EVIDENCE_FILES_CSV,
    SAMPLE_OUTPUT_CSV,
    SAMPLE_REQUESTS_CSV,
    SYSTEM_ACTIVITY_CSV,
)
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence
from ghost.linker import EvidenceLinker
from ghost.rules import default_rule_engine
from ghost.state import StateEvaluator


@dataclass
class UnlinkedStepInfo:
    case_id: str
    step_no: int
    phase: str
    operation: str
    resource_id: str
    expected_evidence_id: str
    subject_email: str
    subject_user_id: str


def run_evaluation() -> dict:
    resolver = IdentityResolver()
    obs, cov, unp, counts = load_all_evidence()
    linker = EvidenceLinker(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV, rule_engine=default_rule_engine)
    evaluator = StateEvaluator(observations=obs, coverages=cov, rule_engine=default_rule_engine)

    # Load manifest for citation validation
    manifest_captured_at = {}
    with open(EVIDENCE_FILES_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            manifest_captured_at[r["file_id"].strip()] = _parse_iso(r["captured_at"])

    cases = list(csv.DictReader(open(SAMPLE_REQUESTS_CSV, newline="", encoding="utf-8")))
    expected_data = {}
    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["case_id"].strip()
            expected_data[cid] = {
                "status": r["deletion_status"].strip(),
                "steps": json.loads(r["steps_json"]),
            }

    total_cases = len(cases)
    total_expected_steps = 0
    total_expected_resources = set()
    total_linked_resources_all_cases = set()
    total_true_positive_resources = set()

    unlinked_steps: list[UnlinkedStepInfo] = []
    linked_steps_count = 0

    finding_matches = 0
    total_expected_findings = 0
    complete_verification_matches = 0
    total_complete_verifications = 0

    citation_matches = 0
    total_citations_checked = 0
    temporal_violations = []

    h7_drifts = []

    for c in cases:
        cid = c["case_id"].strip()
        email = c["email"].strip()
        audit_at = _parse_iso(c["audit_at"])
        reported_at = _parse_iso(c["reported_at"])

        subj = resolver.resolve(email, audit_at)
        linked = linker.link_subject_resources(subj, audit_at=audit_at, reported_at=reported_at)

        exp = expected_data[cid]
        exp_status = exp["status"]
        exp_steps = exp["steps"]

        exp_rids = {s["resource_id"] for s in exp_steps}
        for rid in exp_rids:
            total_expected_resources.add((cid, rid))

        for rid in linked.keys():
            total_linked_resources_all_cases.add((cid, rid))
            if rid in exp_rids:
                total_true_positive_resources.add((cid, rid))

        for s in exp_steps:
            total_expected_steps += 1
            rid = s["resource_id"]
            phase = s["phase"]
            op = s["operation"]
            exp_eid = s.get("evidence_id", "")

            if phase == "FINDING":
                total_expected_findings += 1
            elif exp_status == "COMPLETE" and phase == "VERIFICATION":
                total_complete_verifications += 1

            if rid not in linked:
                unlinked_steps.append(
                    UnlinkedStepInfo(
                        case_id=cid,
                        step_no=s["step_no"],
                        phase=phase,
                        operation=op,
                        resource_id=rid,
                        expected_evidence_id=exp_eid,
                        subject_email=email,
                        subject_user_id=subj.user_id,
                    )
                )
                continue

            linked_steps_count += 1
            r_state = evaluator.determine_resource_state(linked[rid], subj, audit_at)

            # Check H7 drift
            if len(r_state.store_states) > 1:
                stores_found = {st.store: st.state for st in r_state.store_states}
                if "PRESENT_IDENTIFIED" in stores_found.values() and any(
                    x in ("ABSENT", "PRESENT_REDACTED", "PRESENT_ANONYMIZED") for x in stores_found.values()
                ):
                    h7_drifts.append((cid, rid, stores_found))

            if exp_status == "COMPLETE":
                if phase == "VERIFICATION":
                    if r_state.is_compliant:
                        complete_verification_matches += 1
            else:
                if phase == "FINDING":
                    if not r_state.is_compliant:
                        finding_matches += 1

            if exp_eid:
                total_citations_checked += 1
                if r_state.evidence_id == exp_eid:
                    citation_matches += 1

                # Check temporal validity of citation
                if exp_eid in manifest_captured_at:
                    if manifest_captured_at[exp_eid] > audit_at:
                        temporal_violations.append((cid, exp_eid, manifest_captured_at[exp_eid], audit_at))

    # Metrics
    rec_recall = len(total_true_positive_resources) / len(total_expected_resources) if total_expected_resources else 0
    rec_precision = len(total_true_positive_resources) / len(total_linked_resources_all_cases) if total_linked_resources_all_cases else 0
    rec_f1 = (2 * rec_precision * rec_recall / (rec_precision + rec_recall)) if (rec_precision + rec_recall) > 0 else 0

    return {
        "total_cases": total_cases,
        "total_expected_steps": total_expected_steps,
        "linked_steps_count": linked_steps_count,
        "unlinked_steps_count": len(unlinked_steps),
        "unlinked_steps": unlinked_steps,
        "resource_linking": {
            "expected_resources": len(total_expected_resources),
            "linked_candidates": len(total_linked_resources_all_cases),
            "true_positives": len(total_true_positive_resources),
            "precision": rec_precision,
            "recall": rec_recall,
            "f1": rec_f1,
        },
        "findings": {
            "total_expected": total_expected_findings,
            "matches": finding_matches,
            "accuracy_on_linked": finding_matches / total_expected_findings if total_expected_findings else 0,
        },
        "complete_verifications": {
            "total_expected": total_complete_verifications,
            "matches": complete_verification_matches,
            "accuracy_on_linked": complete_verification_matches / total_complete_verifications if total_complete_verifications else 0,
        },
        "citations": {
            "total_checked": total_citations_checked,
            "matches": citation_matches,
            "accuracy": citation_matches / total_citations_checked if total_citations_checked else 0,
        },
        "temporal_violations": temporal_violations,
        "h7_drifts": h7_drifts,
    }


if __name__ == "__main__":
    res = run_evaluation()
    print("=" * 60)
    print("PHASE 6 INDEPENDENT EVALUATION REPORT ON 32 SAMPLES")
    print("=" * 60)
    print(f"Total cases: {res['total_cases']}")
    print(f"Total expected steps: {res['total_expected_steps']}")
    print(f"Linked steps: {res['linked_steps_count']}/{res['total_expected_steps']} ({res['linked_steps_count']/res['total_expected_steps']*100:.1f}%)")
    print(f"Unlinked steps: {res['unlinked_steps_count']}")

    print("\n--- Resource Linking Metrics (Strict Resource-Level Ground Truth) ---")
    rl = res["resource_linking"]
    print(f"Expected unique (case, resource) pairs: {rl['expected_resources']}")
    print(f"Linked candidate (case, resource) pairs: {rl['linked_candidates']}")
    print(f"True positive linked pairs: {rl['true_positives']}")
    print(f"Precision: {rl['precision']*100:.1f}%")
    print(f"Recall:    {rl['recall']*100:.1f}%")
    print(f"F1 Score:  {rl['f1']*100:.1f}%")

    print("\n--- State Determination Accuracy (On Linked Denominator) ---")
    f_res = res["findings"]
    print(f"Finding Violations Correctly Classified: {f_res['matches']}/{f_res['total_expected']} ({f_res['accuracy_on_linked']*100:.1f}%)")
    v_res = res["complete_verifications"]
    print(f"COMPLETE Verifications Correctly Classified: {v_res['matches']}/{v_res['total_expected']} ({v_res['accuracy_on_linked']*100:.1f}%)")

    print("\n--- Evidence Citation Correctness ---")
    c_res = res["citations"]
    print(f"Citations checked: {c_res['total_checked']}")
    print(f"Citations matching expected: {c_res['matches']}/{c_res['total_checked']} ({c_res['accuracy']*100:.1f}%)")
    print(f"Temporal cutoff violations in cited evidence: {len(res['temporal_violations'])}")

    print("\n--- H7 Multi-Store Invariant ---")
    print(f"Multi-store drift instances detected: {len(res['h7_drifts'])}")

    print("\n" + "=" * 60)
    print("INVESTIGATION OF THE UNLINKED EXPECTED STEPS")
    print("=" * 60)
    for u in res["unlinked_steps"]:
        print(f"Case: {u.case_id} | Step: {u.step_no} | Phase: {u.phase} | Op: {u.operation} | Rid: {u.resource_id} | Eid: '{u.expected_evidence_id}' | User: {u.subject_user_id} ({u.subject_email})")
