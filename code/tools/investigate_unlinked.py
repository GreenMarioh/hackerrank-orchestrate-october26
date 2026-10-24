import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

import csv
from ghost.ingest.coordinator import load_all_evidence
from ghost.config import SYSTEM_ACTIVITY_CSV, USER_AUDIT_LOG_CSV, USER_IDENTITIES_CSV
from ghost.identity import IdentityResolver, _parse_iso

obs, cov, unp, _ = load_all_evidence()
activity = list(csv.DictReader(open(SYSTEM_ACTIVITY_CSV, newline='', encoding='utf-8')))
user_audit = list(csv.DictReader(open(USER_AUDIT_LOG_CSV, newline='', encoding='utf-8')))
user_identities = list(csv.DictReader(open(USER_IDENTITIES_CSV, newline='', encoding='utf-8')))

targets = [
    ('case_04', 'account_004', 'user_04', 'thandiwe.n@gmail.com', '2026-09-03T11:45:00Z'),
    ('case_09', 'audit_record_4902', 'user_61', 'k.appiah88@gmail.com', '2026-09-16T12:00:00Z'),
    ('case_18', 'audit_record_6645', 'user_50', 'mori.ren@gmail.com', '2026-09-26T11:00:00Z'),
    ('case_20', 'audit_record_5569', 'user_48', 'akosua.gyasi@gmail.com', '2026-09-26T11:00:00Z'),
]

for cid, rid, uid, email, aat_str in targets:
    aat = _parse_iso(aat_str)
    print(f"\n=======================================================")
    print(f"TARGET: {cid} | rid={rid} | user_id={uid} | email={email} | audit_at={aat_str}")
    print(f"=======================================================")

    # 1. Check direct observations for rid
    obs_for_rid = [o for o in obs if o.resource_id == rid and o.captured_at <= aat]
    print(f"1. Observations for resource_id '{rid}' (captured <= audit_at): {len(obs_for_rid)}")
    for o in obs_for_rid:
        print(f"   file={o.file_id} store={o.store} time={o.captured_at.isoformat()} present={o.present} fields={o.fields}")

    # 2. Check observations containing uid or email
    obs_for_user = [o for o in obs if o.captured_at <= aat and (
        uid in str(o.fields.get('user_id', ''))
        or uid in str(o.fields.get('customer_reference', ''))
        or uid in str(o.fields.get('subject_reference', ''))
        or email.lower() in str(o.fields).lower()
    )]
    print(f"2. Observations matching user_id '{uid}' or email '{email}': {len(obs_for_user)}")
    for o in obs_for_user:
        print(f"   file={o.file_id} rid={o.resource_id} store={o.store} cat={o.category}")

    # 3. Check activity events mentioning rid
    act_for_rid = [a for a in activity if rid in str(a) and _parse_iso(a['event_time']) <= aat]
    print(f"3. Activity events mentioning '{rid}' (<= audit_at): {len(act_for_rid)}")
    for a in act_for_rid:
        print(f"   time={a['event_time']} type={a['event_type']} sys={a['target_system']} details={a['details']}")

    # 4. Check activity events mentioning uid or email
    act_for_user = [a for a in activity if (uid in str(a) or email in str(a)) and _parse_iso(a['event_time']) <= aat]
    print(f"4. Activity events mentioning '{uid}' or '{email}' (<= audit_at): {len(act_for_user)}")
    for a in act_for_user:
        print(f"   time={a['event_time']} type={a['event_type']} sys={a['target_system']} details={a['details']}")
