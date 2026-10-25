"""Experiment: Narrowly test verification gating on medium-confidence activity links."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

import csv
import json
from ghost.config import DATASET_DIR
from ghost.identity import _parse_iso
from main import build_pipeline

def test_narrow_verification():
    engine, requests = build_pipeline(DATASET_DIR)
    
    sample_reqs = {r["case_id"]: r for r in csv.DictReader(open(DATASET_DIR / "sample_deletion_requests.csv", encoding="utf-8"))}
    sample_out = {r["case_id"]: json.loads(r["steps_json"]) for r in csv.DictReader(open(DATASET_DIR / "sample_output.csv", encoding="utf-8"))}

    # Baseline on samples
    print("=== BASELINE EVALUATION ON 32 SAMPLES ===")
    from tools.audit_samples import run_sample_audit
    b_metrics = run_sample_audit()
    print(f"Baseline: Status={b_metrics['status_matches']}/{b_metrics['total_cases']}, Exact={b_metrics['exact_steplist_matches']}/{b_metrics['total_cases']}, Recall={b_metrics['aligned_step_count']}/{b_metrics['total_expected_steps']} ({b_metrics['step_recall']*100:.2f}%), Prec={b_metrics['aligned_step_count']}/{b_metrics['total_generated_steps']} ({b_metrics['step_precision']*100:.2f}%), F1={b_metrics['step_f1']*100:.2f}%")

    # Now let's see what happens if we allow MEDIUM confidence resources in COMPLETE cases ONLY IF:
    # 1. The case has NO high-confidence violations (i.e. is_complete is True)
    # 2. The resource is an account or analytics record whose state in the database at audit_at is ABSENT or ANONYMIZED
    # Let's inspect which cases in 518 dataset would change status or add steps!

    full_reqs = list(csv.DictReader(open(DATASET_DIR / "deletion_requests.csv", encoding="utf-8")))
    print(f"\nAnalyzing 518 cases with narrow verification rule...")

    # Let's check status changes and step additions across all 518 cases
    status_changes = 0
    added_steps_count = 0
    complete_cases_affected = []

    for req in full_reqs:
        cid = req["case_id"]
        audit_at = _parse_iso(req["audit_at"])
        subj = engine.resolver.resolve(req["email"], audit_at)
        if not subj:
            continue
        linked = engine.linker.link_subject_resources(subj, audit_at)
        
        # Check standard result
        res_baseline = engine.audit_case(
            case_id=cid,
            email=req["email"],
            audit_at=audit_at,
            reported_status=req.get("reported_status"),
            reported_at=_parse_iso(req["reported_at"]) if req.get("reported_at") else None,
            request_text=req.get("request_text"),
        )

        # Check medium confidence resources
        med_resources = [lr for lr in linked.values() if lr.confidence == "MEDIUM"]
        if med_resources and res_baseline.deletion_status == "COMPLETE":
            complete_cases_affected.append((cid, len(med_resources), [lr.resource_id for lr in med_resources]))

    print(f"Total COMPLETE cases in full dataset with MEDIUM confidence resources: {len(complete_cases_affected)}")
    for cid, cnt, rids in complete_cases_affected[:10]:
        print(f"  {cid}: {cnt} medium resources -> {rids}")

if __name__ == "__main__":
    test_narrow_verification()
