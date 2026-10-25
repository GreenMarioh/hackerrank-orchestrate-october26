"""Inspect evidence and activity records backing the 35 missing sample resources."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

import csv
import json
from ghost.config import DATASET_DIR
from main import build_pipeline

def main():
    engine, requests = build_pipeline(DATASET_DIR)
    obs_by_res = {}
    for o in engine.linker.observations:
        if o.resource_id:
            obs_by_res.setdefault(o.resource_id, []).append(o)

    act_by_res = {}
    for a in engine.linker.activities:
        rid = a.get("resource_id")
        if rid:
            act_by_res.setdefault(rid, []).append(a)

    sample_out = {r["case_id"]: json.loads(r["steps_json"]) for r in csv.DictReader(open(DATASET_DIR / "sample_output.csv", encoding="utf-8"))}

    sample_reqs = {r["case_id"]: r for r in csv.DictReader(open(DATASET_DIR / "sample_deletion_requests.csv", encoding="utf-8"))}

    target_cases = ["case_01", "case_02", "case_03", "case_04", "case_09", "case_18", "case_21", "case_24", "case_25", "case_26"]

    for cid in target_cases:
        req = sample_reqs[cid]
        audit_at = req["audit_at"]
        print(f"\n=== {cid} (audit_at={audit_at}) ===")
        for s in sample_out[cid]:
            rid = s["resource_id"]
            obs = obs_by_res.get(rid, [])
            acts = act_by_res.get(rid, [])
            evid = s.get("evidence_id", "")
            print(f"  Step: {s['phase']} {s['system_id']} {rid} ({s['operation']}) evid='{evid}' -> obs={len(obs)}, acts={len(acts)}")
            for o in obs:
                print(f"     OBS: file={o.file_id} sys={o.system_id} cap={o.captured_at} fields={list(o.fields.keys())}")
            for a in acts:
                print(f"     ACT: id={a['activity_id']} type={a['event_type']} time={a['event_time']} det={a['details'][:80]}")

if __name__ == "__main__":
    main()
