import csv
import json
from collections import defaultdict
from ghost.config import SYSTEM_ACTIVITY_CSV, SAMPLE_OUTPUT_CSV
from ghost.ingest.coordinator import load_all_evidence
from ghost.rules import default_rule_engine

engine = default_rule_engine
obs, cov, unp, counts = load_all_evidence()

obs_counts = defaultdict(int)
for o in obs:
    cat, _ = engine.categorize_resource(o.resource_id, o.system_id, o.fields, o.category)
    if cat:
        obs_counts[cat] += 1

activity_counts = defaultdict(int)
with open(SYSTEM_ACTIVITY_CSV, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cat, _ = engine.categorize_resource(r["resource_id"], r["source_system"])
        if cat:
            activity_counts[cat] += 1

sample_step_counts = defaultdict(int)
sample_unique_res_counts = defaultdict(int)
seen_case_res = set()
with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cid = r["case_id"].strip()
        steps = json.loads(r["steps_json"])
        for s in steps:
            rid = s["resource_id"]
            cat, _ = engine.categorize_resource(rid, s["system_id"])
            if cat:
                sample_step_counts[cat] += 1
                if (cid, rid) not in seen_case_res:
                    seen_case_res.add((cid, rid))
                    sample_unique_res_counts[cat] += 1

print("| Category               | Evidence Obs | Activity   | Sample Steps | Sample Res |")
print("|------------------------|--------------|------------|--------------|------------|")
for rule in engine.rules.values():
    cat = rule.data_category
    o_c = obs_counts.get(cat, 0)
    a_c = activity_counts.get(cat, 0)
    ss_c = sample_step_counts.get(cat, 0)
    sr_c = sample_unique_res_counts.get(cat, 0)
    print(f"| {cat:<22} | {o_c:<12} | {a_c:<10} | {ss_c:<12} | {sr_c:<10} |")

# Also print data_flow and restore_risk
df_obs = obs_counts.get("DATA_FLOW", 0)
df_act = activity_counts.get("DATA_FLOW", 0)
df_ss = sample_step_counts.get("DATA_FLOW", 0)
df_sr = sample_unique_res_counts.get("DATA_FLOW", 0)
print(f"| {'DATA_FLOW (Active)':<22} | {df_obs:<12} | {df_act:<10} | {df_ss:<12} | {df_sr:<10} |")

rr_obs = obs_counts.get("RESTORE_RISK", 0)
rr_act = activity_counts.get("RESTORE_RISK", 0)
rr_ss = sample_step_counts.get("RESTORE_RISK", 0)
rr_sr = sample_unique_res_counts.get("RESTORE_RISK", 0)
print(f"| {'RESTORE_RISK (Active)':<22} | {rr_obs:<12} | {rr_act:<10} | {rr_ss:<12} | {rr_sr:<10} |")
