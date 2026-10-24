import csv
import json
from collections import defaultdict
from ghost.config import (
    DATASET_DIR, SAMPLE_REQUESTS_CSV, SAMPLE_OUTPUT_CSV, 
    EVIDENCE_FILES_CSV, SYSTEM_ACTIVITY_CSV
)
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence

resolver = IdentityResolver()
obs, cov, unp, counts = load_all_evidence()

# Load 32 sample requests
sample_reqs = {}
with open(SAMPLE_REQUESTS_CSV, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cid = r["case_id"].strip()
        sample_reqs[cid] = {
            "case_id": cid,
            "email": r["email"].strip(),
            "reported_at": _parse_iso(r["reported_at"]),
            "audit_at": _parse_iso(r["audit_at"]),
        }

# Load expected resources per case from sample_output.csv (WITHOUT using evidence_id)
expected_resources_by_case = defaultdict(set)
with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cid = r["case_id"].strip()
        steps = json.loads(r["steps_json"])
        for s in steps:
            expected_resources_by_case[cid].add(s["resource_id"])

total_expected_resources = sum(len(res) for res in expected_resources_by_case.values())

# Load activity
activity = []
with open(SYSTEM_ACTIVITY_CSV, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        activity.append({
            "activity_id": r["activity_id"].strip(),
            "event_time": _parse_iso(r["event_time"]),
            "resource_id": r["resource_id"].strip(),
            "details": r["details"].lower(),
        })

# (a) Link observations WITHOUT cited evidence IDs
# Strategy: match observation fields against subject identity bundle (user_id, all emails, phones, hashes)
# and LINK_RESOURCE_IDENTITY events in activity, and activity time window (+- 2h)
found_resources_by_case = defaultdict(set)

for cid, req in sample_reqs.items():
    ident = resolver.resolve(req["email"], req["audit_at"])
    aliases = {e.lower() for e in ident.all_emails} | {ident.user_id.lower()}
    for p in ident.all_phones:
        aliases.add(p.lower())
    for h in ident.all_hashes:
        aliases.add(h.lower())
    if ident.name:
        aliases.add(ident.name.lower())

    # 1. Match observations across ALL evidence files
    for o in obs:
        # Check if observation captured_at <= audit_at
        if o.captured_at > req["audit_at"]:
            continue
        # Direct identifier match in fields
        f_str = json.dumps(o.fields).lower()
        if any(a in f_str for a in aliases):
            found_resources_by_case[cid].add(o.resource_id)

    # 2. Activity events within window (+- 2h of reported_at)
    rep_ts = req["reported_at"].timestamp()
    for act in activity:
        if act["event_time"] > req["audit_at"]:
            continue
        diff = abs(act["event_time"].timestamp() - rep_ts)
        if diff <= 7200:
            # Check if details matches alias OR resource was already candidate
            if any(a in act["details"] for a in aliases) or act["resource_id"].startswith("data_flow_") or act["resource_id"].startswith("backup_"):
                found_resources_by_case[cid].add(act["resource_id"])

# Compute recall
total_recalled = 0
for cid, expected in expected_resources_by_case.items():
    found = found_resources_by_case[cid]
    recalled = expected & found
    total_recalled += len(recalled)

overall_recall = total_recalled / total_expected_resources if total_expected_resources else 0
print(f"Total expected resource instances: {total_expected_resources}")
print(f"Total recalled without cited evidence IDs: {total_recalled}")
print(f"Overall Recall: {overall_recall:.2%}")

# (b) Time-window measurement
# For each case: candidates in +- 2h window vs expected resources
total_candidates = 0
total_tp_in_window = 0

print("\n--- Per-case Time Window Precision ---")
for cid, req in sorted(sample_reqs.items()):
    rep_ts = req["reported_at"].timestamp()
    expected = expected_resources_by_case[cid]
    window_candidates = set()
    for act in activity:
        if act["event_time"] <= req["audit_at"] and abs(act["event_time"].timestamp() - rep_ts) <= 7200:
            window_candidates.add(act["resource_id"])
    
    tp = len(window_candidates & expected)
    total_candidates += len(window_candidates)
    total_tp_in_window += tp
    prec = tp / len(window_candidates) if window_candidates else 0
    print(f"{cid}: candidates={len(window_candidates):2d}, expected={len(expected):2d}, matched_expected={tp:2d}, precision={prec:.1%}")

overall_window_prec = total_tp_in_window / total_candidates if total_candidates else 0
print(f"\nOverall Time Window: {total_tp_in_window} true positives / {total_candidates} candidates = {overall_window_prec:.2%} precision")
