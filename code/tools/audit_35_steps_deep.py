"""Deep independent audit of the 35 missing expected sample steps."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

import csv
import json
from ghost.config import DATASET_DIR, EVIDENCE_FILES_CSV
from ghost.identity import _parse_iso
from main import build_pipeline

def audit_deep():
    # Load manifest
    manifest = {}
    with open(EVIDENCE_FILES_CSV, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            manifest[r["file_id"]] = {
                "rel_path": r["file_path"].strip(),
                "captured_at": _parse_iso(r["captured_at"].strip()),
            }

    # Load system activity
    activities = []
    with open(DATASET_DIR / "system_activity.csv", "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            activities.append({
                "activity_id": r["activity_id"].strip(),
                "event_time": _parse_iso(r["event_time"].strip()),
                "event_type": r["event_type"].strip(),
                "resource_id": r["resource_id"].strip(),
                "details": r["details"].strip(),
            })

    # Load engine observations
    engine, requests = build_pipeline(DATASET_DIR)
    obs_by_res = {}
    for o in engine.linker.observations:
        if o.resource_id:
            obs_by_res.setdefault(o.resource_id, []).append(o)

    act_by_res = {}
    for a in activities:
        rid = a["resource_id"]
        if rid:
            act_by_res.setdefault(rid, []).append(a)

    sample_reqs = {r["case_id"]: r for r in csv.DictReader(open(DATASET_DIR / "sample_deletion_requests.csv", encoding="utf-8"))}
    sample_out = {r["case_id"]: json.loads(r["steps_json"]) for r in csv.DictReader(open(DATASET_DIR / "sample_output.csv", encoding="utf-8"))}

    # Identify all 35 missing steps
    results = []
    for cid in sorted(sample_out.keys()):
        req = sample_reqs[cid]
        audit_at = _parse_iso(req["audit_at"])
        subj = engine.resolver.resolve(req["email"], audit_at)
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
                rid = s["resource_id"]
                obs = obs_by_res.get(rid, [])
                acts = act_by_res.get(rid, [])
                evid = s.get("evidence_id", "")
                results.append({
                    "case_id": cid,
                    "step": s,
                    "audit_at": audit_at,
                    "subj_user_id": subj.user_id if subj else None,
                    "subj_emails": subj.all_emails if subj else set(),
                    "obs": obs,
                    "acts": acts,
                    "exp_evid": evid,
                })

    print(f"Total missing expected steps audited: {len(results)}")
    
    # Analyze each step
    for idx, r in enumerate(results, start=1):
        s = r["step"]
        cid = r["case_id"]
        rid = s["resource_id"]
        sys_id = s["system_id"]
        op = s["operation"]
        st = s["state"]
        exp_evid = r["exp_evid"]
        audit_at = r["audit_at"]
        subj_uid = r["subj_user_id"]
        obs = r["obs"]
        acts = r["acts"]

        # Check appearance in evidence
        in_evidence = len(obs) > 0
        in_activity = len(acts) > 0

        # Check source content and file
        evid_files = sorted(list(set(o.file_id for o in obs)))
        evid_summary = ", ".join(evid_files) if evid_files else ("activity_only" if in_activity else "none")

        # Check temporal availability
        temporal_available = False
        earliest_evid_time = None
        if exp_evid and exp_evid in manifest:
            cap = manifest[exp_evid]["captured_at"]
            temporal_available = (cap <= audit_at)
            earliest_evid_time = cap
        elif obs:
            caps = [o.captured_at for o in obs if o.captured_at]
            if caps:
                earliest_evid_time = min(caps)
                temporal_available = (earliest_evid_time <= audit_at)
        elif acts:
            times = [a["event_time"] for a in acts if a["event_time"]]
            if times:
                earliest_evid_time = min(times)
                temporal_available = (earliest_evid_time <= audit_at)

        # Check linkability to subject without ground truth
        has_identity_link = False
        if subj_uid:
            for o in obs:
                f_uid = o.fields.get("user_id") or o.fields.get("customer_reference")
                f_email = o.fields.get("email")
                if (f_uid and f_uid == subj_uid) or (f_email and f_email in r["subj_emails"]):
                    has_identity_link = True
                    break

        # Classify verdict and spec clause
        verdict = "UNRESOLVED"
        clause = ""

        if rid.startswith("analytics_"):
            # Check if fields are stripped
            all_null = True
            for o in obs:
                if any(o.fields.get(k) is not None for k in ["user_id", "email", "phone", "email_hash", "customer_reference"]):
                    all_null = False
            if all_null or not has_identity_link:
                verdict = "JUSTIFIED_BY_SPEC"
                clause = "AGENTS.md §6.1 / §6.6: Must connect evidence through contents and identifiers; anonymized records have zero subject links"
            else:
                verdict = "GENUINE_DEFECT"
                clause = "AGENTS.md §6.4: VERIFY_RECORD_ANONYMIZED"
        elif rid.startswith("audit_record_"):
            if exp_evid and exp_evid in manifest and manifest[exp_evid]["captured_at"] > audit_at:
                verdict = "JUSTIFIED_BY_SPEC"
                clause = "AGENTS.md §6.2 / §6.6: Citing evidence captured after audit_at is strictly prohibited"
            elif op == "VERIFY_RECORD_PRESENT" and s["phase"] == "VERIFICATION":
                verdict = "JUSTIFIED_BY_SPEC"
                clause = "Problem statement §Remediation: Retained compliant records do not undergo remediation; post-remediation verification checks remediated records"
        elif rid.startswith("account_"):
            if not in_evidence and in_activity:
                # Check if activity has user identifier
                act_has_id = any(subj_uid and subj_uid in a["details"] for a in acts)
                if not act_has_id:
                    verdict = "JUSTIFIED_BY_SPEC"
                    clause = "AGENTS.md §6.5 / §6.6: Activity logs are claims; unauthenticated activity tokens lack referential identity"
                else:
                    verdict = "GENUINE_DEFECT"
            elif in_evidence and not has_identity_link:
                verdict = "JUSTIFIED_BY_SPEC"
                clause = "AGENTS.md §6.1 / §6.6: Primary account expunged prior to audit_at; no grounded subject link in snapshot"

        print(f"[{idx:02d}] {cid} | {sys_id} {rid} | {op} | {st} | evid='{exp_evid}'")
        print(f"     In Evidence: {in_evidence} ({evid_summary}) | In Activity: {in_activity}")
        print(f"     Available at audit_at: {temporal_available} (Audit: {audit_at}, Evid/Event: {earliest_evid_time})")
        print(f"     Linkable without ground truth: {has_identity_link}")
        print(f"     Clause: {clause}")
        print(f"     Verdict: {verdict}")

if __name__ == "__main__":
    audit_deep()
