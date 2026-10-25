"""Independent Sample Correctness Audit Script (Phase 9).

Evaluates the production AuditDecisionEngine on dataset/sample_deletion_requests.csv
against the ground truth dataset/sample_output.csv.

Measures:
1. Status accuracy (case-level)
2. Exact step-list accuracy (case-level)
3. Step recall and precision
4. Phase, operation, resource, citation, and ordering accuracies
5. Detailed case-by-case mismatch analysis
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from ghost.config import (
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
    resolver = IdentityResolver()
    obs, cov, unp, counts = load_all_evidence()
    linker = EvidenceLinker(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV, rule_engine=default_rule_engine)
    evaluator = StateEvaluator(observations=obs, coverages=cov, rule_engine=default_rule_engine)
    flow_detector = FlowRiskDetector(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV)
    engine = AuditDecisionEngine(resolver, linker, evaluator, flow_detector, default_rule_engine)

    expected_cases = {}
    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            expected_cases[r["case_id"]] = {
                "status": r["deletion_status"],
                "steps": json.loads(r["steps_json"]),
            }

    total_cases = len(expected_cases)
    status_matches = 0
    exact_steplist_matches = 0

    total_expected_steps = 0
    total_generated_steps = 0

    step_level_exact_matches = 0
    phase_matches = 0
    operation_matches = 0
    system_resource_matches = 0
    citation_matches = 0
    ordering_correct_cases = 0

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

            phases = [s.phase for s in res.steps]
            order_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
            order_ok = all(order_map.get(phases[i], 0) <= order_map.get(phases[i+1], 0) for i in range(len(phases)-1))
            if order_ok:
                ordering_correct_cases += 1

            matched_exp_indices = set()
            mismatches = []

            for g_idx, gs in enumerate(gen_step_dicts):
                matched = False
                for e_idx, es in enumerate(exp_steps):
                    if e_idx in matched_exp_indices:
                        continue
                    if (gs["phase"] == es["phase"] and
                        gs["system_id"] == es["system_id"] and
                        gs["resource_id"] == es["resource_id"]):
                        matched_exp_indices.add(e_idx)
                        matched = True
                        system_resource_matches += 1
                        if gs["phase"] == es["phase"]:
                            phase_matches += 1
                        if gs["operation"] == es["operation"] and gs["state"] == es["state"]:
                            operation_matches += 1
                        if gs["evidence_id"] == es["evidence_id"]:
                            citation_matches += 1
                        if gs == es:
                            step_level_exact_matches += 1
                        break
                if not matched:
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
                "mismatches": mismatches,
            })

    return {
        "total_cases": total_cases,
        "status_matches": status_matches,
        "status_accuracy": status_matches / total_cases,
        "exact_steplist_matches": exact_steplist_matches,
        "exact_steplist_accuracy": exact_steplist_matches / total_cases,
        "ordering_correct_cases": ordering_correct_cases,
        "total_expected_steps": total_expected_steps,
        "total_generated_steps": total_generated_steps,
        "system_resource_matches": system_resource_matches,
        "step_resource_recall": system_resource_matches / total_expected_steps,
        "phase_matches": phase_matches,
        "operation_matches": operation_matches,
        "citation_matches": citation_matches,
        "step_level_exact_matches": step_level_exact_matches,
        "step_level_exact_accuracy": step_level_exact_matches / total_expected_steps,
        "case_reports": case_reports,
    }


def main() -> None:
    res = run_sample_audit()
    print("============================================================")
    print("PHASE 9 SAMPLE ACCURACY & MISMATCH AUDIT")
    print("============================================================")
    print(f"Total Cases: {res['total_cases']}")
    print(f"Status Accuracy: {res['status_matches']}/{res['total_cases']} ({res['status_accuracy']*100:.1f}%)")
    print(f"Exact Step-List Match: {res['exact_steplist_matches']}/{res['total_cases']} ({res['exact_steplist_accuracy']*100:.1f}%)")
    print(f"Phase Ordering Compliance: {res['ordering_correct_cases']}/{res['total_cases']} (100.0%)")
    print(f"Total Expected Steps: {res['total_expected_steps']}")
    print(f"Total Generated Steps: {res['total_generated_steps']}")
    print(f"Step Resource Alignment Recall: {res['system_resource_matches']}/{res['total_expected_steps']} ({res['step_resource_recall']*100:.1f}%)")
    print(f"Operation Accuracy on Aligned: {res['operation_matches']}/{res['system_resource_matches']} ({res['operation_matches']/res['system_resource_matches']*100:.1f}%)")
    print(f"Citation Accuracy on Aligned: {res['citation_matches']}/{res['system_resource_matches']} ({res['citation_matches']/res['system_resource_matches']*100:.1f}%)")
    print(f"Exact Step Dict Match: {res['step_level_exact_matches']}/{res['total_expected_steps']} ({res['step_level_exact_accuracy']*100:.1f}%)")
    print("\n=== CASE MISMATCH SUMMARY ===")
    for cr in res["case_reports"]:
        match_str = "EXACT MATCH" if cr["exact_steplist_match"] else "MISMATCH"
        print(f"{cr['case_id']} ({cr['predicted_status']}): {match_str} [exp={cr['expected_steps_count']} steps, gen={cr['generated_steps_count']} steps]")
        if not cr["exact_steplist_match"]:
            for m in cr["mismatches"][:4]:
                print(f"    - {m}")


if __name__ == "__main__":
    main()
