"""Triage all 35 unmatched expected sample steps."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

import csv
import json
from ghost.config import DATASET_DIR
from ghost.identity import _parse_iso
from main import build_pipeline

def main():
    engine, requests = build_pipeline(DATASET_DIR)

    sample_reqs = {r["case_id"]: r for r in csv.DictReader(open(DATASET_DIR / "sample_deletion_requests.csv", encoding="utf-8"))}
    sample_out = {r["case_id"]: json.loads(r["steps_json"]) for r in csv.DictReader(open(DATASET_DIR / "sample_output.csv", encoding="utf-8"))}

    missing_steps = []

    for cid in sorted(sample_out.keys()):
        req = sample_reqs[cid]
        audit_at = _parse_iso(req["audit_at"])
        res = engine.audit_case(
            case_id=cid,
            email=req["email"],
            audit_at=audit_at,
            reported_status=req.get("reported_status"),
            reported_at=_parse_iso(req["reported_at"]) if req.get("reported_at") else None,
            request_text=req.get("request_text"),
        )
        gen_keys = {(s.phase, s.system_id, s.resource_id) for s in res.steps}
        for s in sample_out[cid]:
            k = (s["phase"], s["system_id"], s["resource_id"])
            if k not in gen_keys:
                missing_steps.append((cid, s))

    print(f"Total missing expected steps: {len(missing_steps)}")
    for idx, (cid, s) in enumerate(missing_steps, start=1):
        phase = s["phase"]
        sys_id = s["system_id"]
        res_id = s["resource_id"]
        op = s["operation"]
        st = s["state"]
        evid = s.get("evidence_id", "")
        print(f"{idx:02d}. {cid}: {phase} {sys_id} {res_id} | {op} | {st} | evid='{evid}'")

if __name__ == "__main__":
    main()
