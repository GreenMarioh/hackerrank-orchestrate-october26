import csv
import json
from collections import defaultdict
from ghost.config import (
    DATASET_DIR, SAMPLE_REQUESTS_CSV, SAMPLE_OUTPUT_CSV, 
    EVIDENCE_FILES_CSV, SYSTEM_ACTIVITY_CSV
)
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence
from ghost.rules import default_rule_engine

resolver = IdentityResolver()
engine = default_rule_engine
obs, cov, unp, counts = load_all_evidence()
manifest = {r["file_id"]: r for r in csv.DictReader(open(EVIDENCE_FILES_CSV, encoding="utf-8"))}

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

# Load expected resources per case
expected_resources_by_case = defaultdict(set)
case_steps = defaultdict(list)
with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        cid = r["case_id"].strip()
        steps = json.loads(r["steps_json"])
        for s in steps:
            expected_resources_by_case[cid].add(s["resource_id"])
            case_steps[cid].append(s)

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

# Unassisted Alias Linking
found_by_alias = defaultdict(set)
for cid, req in sample_reqs.items():
    ident = resolver.resolve(req["email"], req["audit_at"])
    aliases = {e.lower() for e in ident.all_emails} | {ident.user_id.lower()}
    for p in ident.all_phones: aliases.add(p.lower())
    for h in ident.all_hashes: aliases.add(h.lower())
    if ident.name: aliases.add(ident.name.lower())

    for o in obs:
        if o.captured_at > req["audit_at"]:
            continue
        f_str = json.dumps(o.fields).lower()
        if any(a in f_str for a in aliases):
            found_by_alias[cid].add(o.resource_id)

    # Activity alias match
    rep_ts = req["reported_at"].timestamp()
    for act in activity:
        if act["event_time"] > req["audit_at"]:
            continue
        if any(a in act["details"] for a in aliases):
            found_by_alias[cid].add(act["resource_id"])

# Find the unlinked resources
unlinked = []
for cid, expected in sorted(expected_resources_by_case.items()):
    missing = expected - found_by_alias[cid]
    for rid in missing:
        r_steps = [s for s in case_steps[cid] if s["resource_id"] == rid]
        ev_ids = [s.get("evidence_id", "") for s in r_steps]
        unlinked.append((cid, rid, r_steps, ev_ids))

print(f"Total expected resource instances: {total_expected_resources}")
print(f"Total unlinked instances without cited evidence: {len(unlinked)}")

by_cat_reason = defaultdict(int)
for cid, rid, r_steps, ev_ids in unlinked:
    cat, _ = engine.categorize_resource(rid)
    non_empty_ev = [e for e in ev_ids if e]
    if not non_empty_ev:
        reason = "Future remediation/verification only (evidence_id='')"
    elif any(manifest.get(e, {}).get("file_path", "").endswith(".png") for e in non_empty_ev):
        reason = "Cited evidence is PNG screenshot (offline without API key)"
    else:
        reason = "Evidence cited has no direct alias (linked via activity/service)"
    by_cat_reason[(cat, reason)] += 1

print("\n--- Breakdown of Unlinked Resources by Category and Reason ---")
print(f"| {'Category':<22} | {'Count':<6} | {'Reason':<60} |")
print("|" + "-"*24 + "|" + "-"*8 + "|" + "-"*62 + "|")
for (cat, reason), cnt in sorted(by_cat_reason.items()):
    print(f"| {cat:<22} | {cnt:<6} | {reason:<60} |")

# Type-constrained window linking:
# Constraint: Only consider activity candidates whose resource category matches expected categories
# for a user deletion case (e.g. USER_PROFILE, SEARCH_INDEX_ENTRY, SUPPORT_MESSAGE, ANALYTICS_PROFILE,
# USER_EXPORT, DATA_FLOW, BACKUP_ARCHIVE, SECURITY_AUDIT_LOG, ACCOUNT_TOMBSTONE)
print("\n--- Type-Constrained Time-Window Linking ---")
print(f"| {'Case ID':<8} | {'Candidates':<11} | {'Expected':<9} | {'Matched':<8} | {'Precision':<10} |")
print("|" + "-"*10 + "|" + "-"*13 + "|" + "-"*11 + "|" + "-"*10 + "|" + "-"*12 + "|")

total_tc_candidates = 0
total_tc_tp = 0

for cid, req in sorted(sample_reqs.items()):
    rep_ts = req["reported_at"].timestamp()
    expected = expected_resources_by_case[cid]
    expected_categories = {engine.categorize_resource(r)[0] for r in expected}

    window_candidates = set()
    for act in activity:
        if act["event_time"] <= req["audit_at"] and abs(act["event_time"].timestamp() - rep_ts) <= 7200:
            act_cat, _ = engine.categorize_resource(act["resource_id"])
            # Constrain to expected resource categories for this case
            if act_cat in expected_categories:
                window_candidates.add(act["resource_id"])

    tp = len(window_candidates & expected)
    total_tc_candidates += len(window_candidates)
    total_tc_tp += tp
    prec = tp / len(window_candidates) if window_candidates else 0
    print(f"| {cid:<8} | {len(window_candidates):<11} | {len(expected):<9} | {tp:<8} | {prec:<9.1%} |")

overall_tc_prec = total_tc_tp / total_tc_candidates if total_tc_candidates else 0
print(f"\nOverall Type-Constrained Window Precision: {total_tc_tp} / {total_tc_candidates} = {overall_tc_prec:.2%}")
