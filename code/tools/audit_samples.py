"""Independent Sample Correctness & Invariant Audit Tool (Phase 10).

Evaluates the production AuditDecisionEngine on dataset/sample_deletion_requests.csv
against the ground truth dataset/sample_output.csv.

Computes mathematically distinct, correctly named metrics:
1. Case-Level Status Accuracy
2. Exact Step-List Match Rate
3. Expected-Step Alignment Precision, Recall, and F1 (grounded on (phase, system_id, resource_id))
4. Operation and State Match Accuracy on Aligned Steps
5. System & Resource Alignment Precision and Recall
6. Evidence ID Exact Match Accuracy on Aligned Steps
7. Citation Existence Validity (verifying cited evidence exists in dataset)
8. Temporal Citation Validity (verifying cited evidence was captured <= audit_at)
9. Phase & Step Numbering Ordering Compliance (independent of semantic correctness)

Diagnostic table for all cases with missing/unexpected steps and root causes.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from ghost.config import (
    EVIDENCE_FILES_CSV,
    SAMPLE_OUTPUT_CSV,
    SAMPLE_REQUESTS_CSV,
    SYSTEM_ACTIVITY_CSV,
)
from ghost.decision import AuditDecisionEngine
from ghost.flows import FlowRiskDetector
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence
from ghost.linker import EvidenceLinker
from ghost.rules import default_rule_engine
from ghost.state import StateEvaluator


def run_sample_audit() -> dict:
    # 1. Load manifest times for temporal validation
    manifest_times: dict[str, Any] = {}
    with open(EVIDENCE_FILES_CSV, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            manifest_times[r["file_id"]] = _parse_iso(r["captured_at"])

    # 2. Initialize production engines
    resolver = IdentityResolver()
    obs, cov, unp, counts = load_all_evidence()
    linker = EvidenceLinker(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV, rule_engine=default_rule_engine)
    evaluator = StateEvaluator(observations=obs, coverages=cov, rule_engine=default_rule_engine)
    flow_detector = FlowRiskDetector(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV)
    engine = AuditDecisionEngine(resolver, linker, evaluator, flow_detector, default_rule_engine)

    # 3. Load expected ground truth
    expected_cases: dict[str, dict] = {}
    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            expected_cases[r["case_id"]] = {
                "status": r["deletion_status"],
                "steps": json.loads(r["steps_json"]),
            }

    total_cases = len(expected_cases)
    status_matches = 0
    exact_steplist_matches = 0
    ordering_compliant_cases = 0

    total_expected_steps = 0
    total_generated_steps = 0

    # Step alignment metrics
    aligned_step_count = 0
    operation_matches_on_aligned = 0
    state_matches_on_aligned = 0
    operation_and_state_matches_on_aligned = 0
    evidence_id_matches_on_aligned = 0
    exact_dict_matches_on_aligned = 0

    # Citation validity across ALL generated steps
    total_generated_citations = 0
    citations_existing = 0
    citations_temporal_valid = 0
    citations_temporal_leaks = 0

    case_reports = []

    with open(SAMPLE_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["case_id"]
            email = r["email"]
            audit_at = _parse_iso(r["audit_at"])
            rep_st = r.get("reported_status")
            rep_at = _parse_iso(r["reported_at"]) if r.get("reported_at") else None
            req_txt = r.get("request_text", "")

            res = engine.audit_case(cid, email, audit_at, rep_st, rep_at, req_txt)
            exp = expected_cases[cid]
            exp_status = exp["status"]
            exp_steps = exp["steps"]

            is_status_match = (res.deletion_status == exp_status)
            if is_status_match:
                status_matches += 1

            gen_step_dicts = [s.to_dict() for s in res.steps]
            total_expected_steps += len(exp_steps)
            total_generated_steps += len(gen_step_dicts)

            is_exact_steplist = (gen_step_dicts == exp_steps)
            if is_exact_steplist:
                exact_steplist_matches += 1

            # Phase & numbering ordering check
            phases = [s.phase for s in res.steps]
            order_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
            phase_order_ok = all(order_map.get(phases[i], 0) <= order_map.get(phases[i+1], 0) for i in range(len(phases)-1))
            numbering_ok = all(s.step_no == (i + 1) for i, s in enumerate(res.steps))
            if phase_order_ok and numbering_ok:
                ordering_compliant_cases += 1

            # Check citations on generated steps
            for gs in gen_step_dicts:
                ev_id = gs.get("evidence_id")
                if ev_id:
                    total_generated_citations += 1
                    if ev_id in manifest_times:
                        citations_existing += 1
                        m_time = manifest_times[ev_id]
                        if m_time and m_time <= audit_at:
                            citations_temporal_valid += 1
                        else:
                            citations_temporal_leaks += 1
                    else:
                        citations_temporal_leaks += 1

            # Alignment matching between generated and expected steps
            matched_exp_indices = set()
            matched_gen_indices = set()
            mismatches = []

            for g_idx, gs in enumerate(gen_step_dicts):
                for e_idx, es in enumerate(exp_steps):
                    if e_idx in matched_exp_indices:
                        continue
                    # Alignment key: (phase, system_id, resource_id)
                    if (gs["phase"] == es["phase"] and
                        gs["system_id"] == es["system_id"] and
                        gs["resource_id"] == es["resource_id"]):
                        matched_exp_indices.add(e_idx)
                        matched_gen_indices.add(g_idx)
                        aligned_step_count += 1

                        if gs["operation"] == es["operation"]:
                            operation_matches_on_aligned += 1
                        if gs["state"] == es["state"]:
                            state_matches_on_aligned += 1
                        if gs["operation"] == es["operation"] and gs["state"] == es["state"]:
                            operation_and_state_matches_on_aligned += 1
                        if gs["evidence_id"] == es["evidence_id"]:
                            evidence_id_matches_on_aligned += 1
                        if gs == es:
                            exact_dict_matches_on_aligned += 1
                        break

            for g_idx, gs in enumerate(gen_step_dicts):
                if g_idx not in matched_gen_indices:
                    mismatches.append(f"Unexpected step: phase={gs.get('phase')} sys={gs.get('system_id')} res={gs.get('resource_id')} op={gs.get('operation')} evid='{gs.get('evidence_id')}'")

            for e_idx, es in enumerate(exp_steps):
                if e_idx not in matched_exp_indices:
                    mismatches.append(f"Missing step: phase={es.get('phase')} sys={es.get('system_id')} res={es.get('resource_id')} op={es.get('operation')} evid='{es.get('evidence_id')}'")

            case_reports.append({
                "case_id": cid,
                "expected_status": exp_status,
                "predicted_status": res.deletion_status,
                "status_match": is_status_match,
                "expected_steps_count": len(exp_steps),
                "generated_steps_count": len(gen_step_dicts),
                "exact_steplist_match": is_exact_steplist,
                "missing_steps": [exp_steps[i] for i in range(len(exp_steps)) if i not in matched_exp_indices],
                "unexpected_steps": [gen_step_dicts[i] for i in range(len(gen_step_dicts)) if i not in matched_gen_indices],
                "mismatches": mismatches,
            })

    step_precision = aligned_step_count / total_generated_steps if total_generated_steps else 0.0
    step_recall = aligned_step_count / total_expected_steps if total_expected_steps else 0.0
    step_f1 = (2 * step_precision * step_recall / (step_precision + step_recall)) if (step_precision + step_recall) else 0.0

    return {
        "total_cases": total_cases,
        "status_matches": status_matches,
        "status_accuracy": status_matches / total_cases,
        "exact_steplist_matches": exact_steplist_matches,
        "exact_steplist_accuracy": exact_steplist_matches / total_cases,
        "ordering_compliant_cases": ordering_compliant_cases,
        "ordering_compliance_rate": ordering_compliant_cases / total_cases,
        "total_expected_steps": total_expected_steps,
        "total_generated_steps": total_generated_steps,
        "aligned_step_count": aligned_step_count,
        "step_precision": step_precision,
        "step_recall": step_recall,
        "step_f1": step_f1,
        "operation_matches_on_aligned": operation_matches_on_aligned,
        "operation_accuracy_on_aligned": operation_matches_on_aligned / aligned_step_count if aligned_step_count else 0.0,
        "state_matches_on_aligned": state_matches_on_aligned,
        "state_accuracy_on_aligned": state_matches_on_aligned / aligned_step_count if aligned_step_count else 0.0,
        "operation_and_state_matches_on_aligned": operation_and_state_matches_on_aligned,
        "operation_and_state_accuracy_on_aligned": operation_and_state_matches_on_aligned / aligned_step_count if aligned_step_count else 0.0,
        "evidence_id_matches_on_aligned": evidence_id_matches_on_aligned,
        "evidence_id_match_rate_on_aligned": evidence_id_matches_on_aligned / aligned_step_count if aligned_step_count else 0.0,
        "exact_dict_matches_on_aligned": exact_dict_matches_on_aligned,
        "exact_dict_match_rate_on_expected": exact_dict_matches_on_aligned / total_expected_steps if total_expected_steps else 0.0,
        "total_generated_citations": total_generated_citations,
        "citations_existing": citations_existing,
        "citation_existence_rate": citations_existing / total_generated_citations if total_generated_citations else 1.0,
        "citations_temporal_valid": citations_temporal_valid,
        "temporal_validity_rate": citations_temporal_valid / total_generated_citations if total_generated_citations else 1.0,
        "citations_temporal_leaks": citations_temporal_leaks,
        "case_reports": case_reports,
    }


def main() -> None:
    res = run_sample_audit()
    print("================================================================================")
    print("PHASE 10 SAMPLE CORRECTNESS & EVALUATION METRICS REPORT")
    print("================================================================================")
    print(f"Total Cases Evaluated: {res['total_cases']}")
    print(f"1. Case-Level Status Accuracy: {res['status_matches']}/{res['total_cases']} ({res['status_accuracy']*100:.2f}%)")
    print(f"2. Exact Step-List Match Rate: {res['exact_steplist_matches']}/{res['total_cases']} ({res['exact_steplist_accuracy']*100:.2f}%)")
    print(f"3. Phase & Numbering Ordering Compliance: {res['ordering_compliant_cases']}/{res['total_cases']} ({res['ordering_compliance_rate']*100:.2f}%)")
    print(f"4. Step Resource Alignment Recall: {res['aligned_step_count']}/{res['total_expected_steps']} ({res['step_recall']*100:.2f}%)")
    print(f"5. Step Resource Alignment Precision: {res['aligned_step_count']}/{res['total_generated_steps']} ({res['step_precision']*100:.2f}%)")
    print(f"6. Step Resource Alignment F1 Score: {res['step_f1']*100:.2f}%")
    print(f"7. Operation Accuracy on Aligned Steps: {res['operation_matches_on_aligned']}/{res['aligned_step_count']} ({res['operation_accuracy_on_aligned']*100:.2f}%)")
    print(f"8. State Accuracy on Aligned Steps: {res['state_matches_on_aligned']}/{res['aligned_step_count']} ({res['state_accuracy_on_aligned']*100:.2f}%)")
    print(f"9. Operation & State Accuracy on Aligned: {res['operation_and_state_matches_on_aligned']}/{res['aligned_step_count']} ({res['operation_and_state_accuracy_on_aligned']*100:.2f}%)")
    print(f"10. Evidence ID Match on Aligned: {res['evidence_id_matches_on_aligned']}/{res['aligned_step_count']} ({res['evidence_id_match_rate_on_aligned']*100:.2f}%)")
    print(f"11. Exact Step Dictionary Match Rate: {res['exact_dict_matches_on_aligned']}/{res['total_expected_steps']} ({res['exact_dict_match_rate_on_expected']*100:.2f}%)")
    print(f"12. Citation Existence Validity: {res['citations_existing']}/{res['total_generated_citations']} ({res['citation_existence_rate']*100:.2f}%)")
    print(f"13. Temporal Citation Validity: {res['citations_temporal_valid']}/{res['total_generated_citations']} ({res['temporal_validity_rate']*100:.2f}%)")
    print(f"    - Temporal Citation Leaks Detected: {res['citations_temporal_leaks']}")
    print("\n================================================================================")
    print("CASE MISMATCH SUMMARY")
    print("================================================================================")
    for cr in res["case_reports"]:
        match_str = "EXACT MATCH" if cr["exact_steplist_match"] else "MISMATCH"
        print(f"{cr['case_id']} ({cr['predicted_status']}): {match_str} [exp={cr['expected_steps_count']} steps, gen={cr['generated_steps_count']} steps]")
        if not cr["exact_steplist_match"]:
            for m in cr["mismatches"][:4]:
                print(f"    - {m}")


if __name__ == "__main__":
    main()
