"""Generate diagnostic table script."""
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


def main():
    expected_cases = {}
    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            expected_cases[r["case_id"]] = {
                "status": r["deletion_status"],
                "steps": json.loads(r["steps_json"]),
            }

    resolver = IdentityResolver()
    obs, cov, unp, counts = load_all_evidence()
    linker = EvidenceLinker(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV, rule_engine=default_rule_engine)
    evaluator = StateEvaluator(observations=obs, coverages=cov, rule_engine=default_rule_engine)
    flow_detector = FlowRiskDetector(observations=obs, activity_path=SYSTEM_ACTIVITY_CSV)
    engine = AuditDecisionEngine(resolver, linker, evaluator, flow_detector, default_rule_engine)

    print("| Case ID | Exp St | Gen St | Exp Steps | Gen Steps | Missing Steps | Unexpected Steps | Root Cause Category |")
    print("|---|---|---|---|---|---|---|---|")

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
            exp_steps = exp["steps"]
            gen_steps = [s.to_dict() for s in res.steps]

            if gen_steps == exp_steps:
                continue

            matched_exp = set()
            matched_gen = set()
            for g_i, gs in enumerate(gen_steps):
                for e_i, es in enumerate(exp_steps):
                    if e_i in matched_exp:
                        continue
                    if (gs["phase"], gs["system_id"], gs["resource_id"]) == (es["phase"], es["system_id"], es["resource_id"]):
                        matched_exp.add(e_i)
                        matched_gen.add(g_i)
                        break

            missing = [exp_steps[i] for i in range(len(exp_steps)) if i not in matched_exp]
            unexpected = [gen_steps[i] for i in range(len(gen_steps)) if i not in matched_gen]

            rc = []
            if any(m["system_id"] == "account_service" and m["operation"] == "VERIFY_RECORD_ABSENT" for m in missing):
                rc.append("CLEAN_ACCOUNT_VERIFICATION_OMITTED")
            if any(m["system_id"] == "security_service" and m["operation"] == "VERIFY_RECORD_PRESENT" for m in missing):
                rc.append("SECURITY_AUDIT_LOG_RETAINED_OMITTED")
            if any(m["system_id"] == "analytics_platform" for m in missing):
                rc.append("ANALYTICS_PROFILE_VERIFICATION_OMITTED")
            if any(u["system_id"] == "legal_service" for u in unexpected):
                rc.append("MULTI_SUBJECT_PDF_REGISTER_LINKED")
            if any(u["resource_id"] == "account_6523" for u in unexpected):
                rc.append("HISTORICAL_ACCOUNT_SUPERSEDED")
            if not rc:
                rc.append("OTHER_OP_MISMATCH")

            miss_summary = "; ".join([f"{m['phase']} {m['resource_id']} ({m['operation']})" for m in missing]) or "None"
            unexp_summary = "; ".join([f"{u['phase']} {u['resource_id']} ({u['operation']})" for u in unexpected]) or "None"

            print(f"| {cid} | {exp['status']} | {res.deletion_status} | {len(exp_steps)} | {len(gen_steps)} | {miss_summary} | {unexp_summary} | {' + '.join(rc)} |")


if __name__ == "__main__":
    main()
