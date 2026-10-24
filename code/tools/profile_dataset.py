"""
profile_dataset.py  — Phase 1: dataset profiling and hypothesis tests.

Run from repo root:
    python code/tools/profile_dataset.py

Exits non-zero if any REQUIRED INVARIANT fails.
All [HYPOTHESIS] results are printed; the script does not fail on a hypothesis;
it marks each as CONFIRMED / REJECTED / PARTIAL with counter-examples.

Development only — reads sample_output.csv for hypothesis validation.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import textwrap
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Repo root resolution ───────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"

sys.path.insert(0, str(REPO_ROOT / "code"))

REQUIRED_FAILURES: list[str] = []   # accumulate invariant failures


def fail(msg: str) -> None:
    REQUIRED_FAILURES.append(msg)
    print(f"  [FAIL] {msg}")


def ok(msg: str) -> None:
    print(f"  [OK]   {msg}")


def section(title: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {title}")
    print("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def sha256_of_email(email: str) -> str:
    return hashlib.sha256(email.lower().encode()).hexdigest()


def parse_ts(ts: str) -> datetime | None:
    """Parse ISO-8601 or similar timestamp; return UTC datetime or None."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


# ══════════════════════════════════════════════════════════════════════════════
# §1 — Verified facts re-check
# ══════════════════════════════════════════════════════════════════════════════

def verify_requests() -> list[dict[str, str]]:
    section("§1.1  deletion_requests.csv — verified facts")
    rows = read_csv(DATASET_DIR / "deletion_requests.csv")
    n = len(rows)
    print(f"  Row count: {n}")
    if n != 518:
        fail(f"Expected 518 deletion requests, got {n}")
    else:
        ok("518 rows")

    # No nulls
    nulls = [(r["case_id"], k) for r in rows for k, v in r.items() if not v.strip()]
    if nulls:
        fail(f"Null/empty fields: {nulls[:5]}")
    else:
        ok("No null/empty fields")

    # Status distribution
    status_dist = Counter(r["reported_status"] for r in rows)
    print(f"  reported_status distribution: {dict(status_dist)}")
    expected = {"COMPLETE": 254, "PARTIALLY_COMPLETE": 152, "NOT_STARTED": 112}
    for k, v in expected.items():
        if status_dist.get(k) != v:
            fail(f"  reported_status[{k}] expected {v}, got {status_dist.get(k)}")
        else:
            ok(f"  reported_status[{k}]={v}")

    # Date ordering: requested_at ≤ reported_at ≤ audit_at
    bad_dates = []
    for r in rows:
        req = parse_ts(r["requested_at"])
        rep = parse_ts(r["reported_at"])
        aud = parse_ts(r["audit_at"])
        if req and rep and aud:
            if not (req <= rep <= aud):
                bad_dates.append(r["case_id"])
    if bad_dates:
        fail(f"Date ordering violated for {len(bad_dates)} cases: {bad_dates[:5]}")
    else:
        ok("requested_at <= reported_at <= audit_at for all rows")

    # Unique case_id
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)):
        fail("Duplicate case_ids detected")
    else:
        ok("All case_ids unique")

    # Uppercase emails
    upper_emails = [r["email"] for r in rows if r["email"] != r["email"].lower()]
    print(f"  Emails with uppercase letters: {len(upper_emails)} (expected ~20)")
    if len(upper_emails) == 0:
        fail("Expected some uppercase emails, found none")
    else:
        ok(f"Uppercase email count: {len(upper_emails)}")

    # Sort-order check: plain str sort
    sorted_ids = sorted(ids, key=str)
    if ids != sorted_ids:
        print(f"  NOTE: deletion_requests.csv is NOT in plain string sort order. "
              f"First mis-sort: {next((a for a,b in zip(ids, sorted_ids) if a!=b), None)}")
    else:
        ok("deletion_requests.csv already in plain string sort order")

    # Duplicate subject (same email different audit_at)
    email_cases: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        email_cases[r["email"].strip().lower()].append(r["case_id"])
    multi = {e: cs for e, cs in email_cases.items() if len(cs) > 1}
    print(f"  Emails appearing in multiple cases: {len(multi)}")
    for e, cs in list(multi.items())[:3]:
        print(f"    {e}: {cs}")

    return rows


def verify_identities(requests: list[dict[str, str]]) -> dict[str, dict]:
    section("§1.1  user_identities.csv — verified facts")
    rows = read_csv(DATASET_DIR / "user_identities.csv")
    print(f"  Row count: {len(rows)}")
    id_map: dict[str, dict] = {r["user_id"]: r for r in rows}

    # email_hash = SHA-256(lowercased email)
    mismatches = []
    for r in rows:
        email = r.get("email", "").strip().lower()
        stored_hash = r.get("email_hash", "").strip().lower()
        computed = sha256_of_email(email)
        if stored_hash and stored_hash != computed:
            mismatches.append((r["user_id"], stored_hash, computed))
    if mismatches:
        fail(f"email_hash mismatches: {mismatches[:3]}")
    else:
        ok(f"email_hash = SHA-256(lowercase email) for all {len(rows)} identities")

    # Names shared across users
    name_counts = Counter(r.get("name", "").strip() for r in rows if r.get("name"))
    shared_names = {n: c for n, c in name_counts.items() if c > 1}
    print(f"  Users sharing a name with another user: {sum(shared_names.values())} "
          f"across {len(shared_names)} distinct names")
    if len(shared_names) < 5:
        print(f"  WARNING: Expected ~6 shared names, got {len(shared_names)}")

    # Historical email coverage
    audit_rows = read_csv(DATASET_DIR / "user_audit_log.csv")
    email_change_rows = [r for r in audit_rows if r.get("field_name") == "email"]
    historical_emails = set()
    for r in email_change_rows:
        historical_emails.add(r.get("old_value", "").strip().lower())
        historical_emails.add(r.get("new_value", "").strip().lower())
    current_emails = {r.get("email", "").strip().lower() for r in rows}

    # Count how many request emails match only historical (not current) identities
    req_rows = read_csv(DATASET_DIR / "deletion_requests.csv")
    historical_only = 0
    for req in req_rows:
        email = req["email"].strip().lower()
        if email not in current_emails and email in historical_emails:
            historical_only += 1
    print(f"  Request emails matching only historical address: {historical_only} (expected ~100)")
    if historical_only < 80 or historical_only > 120:
        print(f"  WARNING: Expected ~100 historical-only emails, got {historical_only}")
    else:
        ok(f"Historical-only request emails: {historical_only}")

    return id_map


def verify_audit_log() -> list[dict[str, str]]:
    section("§1.1  user_audit_log.csv")
    rows = read_csv(DATASET_DIR / "user_audit_log.csv")
    print(f"  Row count: {len(rows)}")

    # Verify every email hash in audit log is explained by a known email
    email_changes = [r for r in rows if r.get("field_name") == "email"]
    known_emails: set[str] = set()
    for r in read_csv(DATASET_DIR / "user_identities.csv"):
        known_emails.add(r.get("email", "").strip().lower())
    for r in email_changes:
        known_emails.add(r.get("old_value", "").strip().lower())
        known_emails.add(r.get("new_value", "").strip().lower())

    hash_rows = [r for r in rows if r.get("field_name") == "email_hash"]
    unexplained = []
    for r in hash_rows:
        stored = r.get("new_value", "").strip().lower()
        if stored and not any(sha256_of_email(e) == stored for e in known_emails):
            unexplained.append(stored[:12])
    if unexplained:
        print(f"  Unexplained email_hash values in audit log: {len(unexplained)} "
              f"(first: {unexplained[:3]})")
    else:
        ok("All email_hashes in audit log explained by known emails")

    return rows


def verify_activity() -> list[dict[str, str]]:
    section("§1.1  system_activity.csv — verified facts")
    rows = read_csv(DATASET_DIR / "system_activity.csv")
    n = len(rows)
    print(f"  Row count: {n} (expected 4011)")
    if n != 4011:
        print(f"  NOTE: Expected 4011 events, got {n}")
    else:
        ok("4011 activity events")

    # event_type inventory
    event_types = Counter(r["event_type"] for r in rows)
    print(f"  Distinct event_types ({len(event_types)}): {dict(event_types.most_common(20))}")
    if len(event_types) != 17:
        print(f"  NOTE: Expected 17 event types, got {len(event_types)}")
    else:
        ok("17 distinct event_types")

    # reported_result distribution
    result_dist = Counter(r.get("reported_result","") for r in rows)
    print(f"  reported_result distribution: {dict(result_dist)}")

    # LINK_RESOURCE_IDENTITY count
    link_events = [r for r in rows if r["event_type"] == "LINK_RESOURCE_IDENTITY"]
    print(f"  LINK_RESOURCE_IDENTITY events: {len(link_events)} (expected 12)")
    if len(link_events) != 12:
        print(f"  NOTE: Expected 12, got {len(link_events)}")
    else:
        ok("12 LINK_RESOURCE_IDENTITY events")

    # CLASSIFY_REQUEST events
    classify = [r for r in rows if r["event_type"] == "CLASSIFY_REQUEST"]
    print(f"  CLASSIFY_REQUEST events: {len(classify)} (expected 10 for non-deletion)")

    return rows


def verify_rules() -> list[dict[str, str]]:
    section("§1.1  deletion_rules.csv")
    rows = read_csv(DATASET_DIR / "deletion_rules.csv")
    print(f"  Row count: {len(rows)} (expected 15)")
    if len(rows) != 15:
        fail(f"Expected 15 deletion rules, got {len(rows)}")
    else:
        ok("15 rules")
    for r in rows:
        print(f"    {r.get('rule_id','?'):10s}  {r.get('data_category','?'):30s}  {r.get('required_action','?')}")
    return rows


def verify_evidence_manifest() -> list[dict[str, str]]:
    section("§1.1  evidence_files.csv manifest")
    rows = read_csv(DATASET_DIR / "evidence_files.csv")
    n = len(rows)
    print(f"  Manifest row count: {n} (expected 94)")
    if n != 94:
        print(f"  NOTE: Expected 94 evidence files, got {n}")
    else:
        ok("94 evidence files")

    # Extension breakdown
    ext_counter: Counter = Counter()
    missing: list[str] = []
    for r in rows:
        p = DATASET_DIR / r["file_path"].replace("dataset/", "").replace("dataset\\", "")
        ext_counter[p.suffix.lower()] += 1
        if not p.exists():
            missing.append(r["file_id"])
    print(f"  Extension breakdown: {dict(ext_counter)}")
    if missing:
        fail(f"Missing evidence files ({len(missing)}): {missing[:5]}")
    else:
        ok("All manifest files exist on disk")
    return rows


# ══════════════════════════════════════════════════════════════════════════════
# §2 — Evidence inventory
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_evidence_path(file_path_col: str) -> Path:
    """Resolve a manifest file_path to an absolute path."""
    # Normalise: strip leading 'dataset/'
    rel = file_path_col.replace("\\", "/")
    for prefix in ("dataset/", "dataset\\"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    return DATASET_DIR / rel


def inventory_sql_files(manifest: list[dict[str, str]]) -> None:
    section("§2  SQL evidence files — table topology")
    sql_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".sql"]
    print(f"  SQL files: {len(sql_rows)} (expected 24)")
    for r in sql_rows:
        path = _resolve_evidence_path(r["file_path"])
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            # Topology hint from header comment
            topology = "unknown"
            for line in raw.splitlines()[:10]:
                low = line.lower()
                if "primary" in low:
                    topology = "primary"
                elif "failover" in low:
                    topology = "failover_replica"
                elif "regional" in low:
                    topology = "regional_replica"
                elif "reporting" in low:
                    topology = "reporting_replica"
                if topology != "unknown":
                    break

            # Parse with sqlite3
            conn = sqlite3.connect(":memory:")
            conn.executescript(raw)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            total_rows = sum(
                conn.execute(f"SELECT COUNT(*) FROM \"{t}\"").fetchone()[0]
                for t in table_names
            )
            conn.close()
            print(f"    {r['file_id']:15s}  topology={topology:20s}  "
                  f"tables={table_names}  rows={total_rows}")
        except Exception as exc:
            print(f"    {r['file_id']:15s}  ERROR: {exc}")


def inventory_json_files(manifest: list[dict[str, str]]) -> None:
    section("§2  JSON evidence files — shape survey")
    json_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".json"]
    print(f"  JSON files: {len(json_rows)} (expected 28)")
    for r in json_rows:
        path = _resolve_evidence_path(r["file_path"])
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            top_keys = list(data.keys()) if isinstance(data, dict) else [f"list[{len(data)}]"]
            # Count records generically
            rec_count = _count_json_records(data)
            print(f"    {r['file_id']:15s}  top_keys={top_keys[:6]}  ~{rec_count} records")
        except Exception as exc:
            print(f"    {r['file_id']:15s}  ERROR: {exc}")


def _count_json_records(obj: Any, depth: int = 0) -> int:
    """Recursively count objects that look like records (have resource_id)."""
    if depth > 5:
        return 0
    if isinstance(obj, dict):
        if "resource_id" in obj:
            return 1
        return sum(_count_json_records(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return sum(_count_json_records(item, depth + 1) for item in obj)
    return 0


def inventory_log_files(manifest: list[dict[str, str]]) -> None:
    section("§2  Log evidence files — dialect survey")
    log_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".log"]
    print(f"  Log files: {len(log_rows)} (expected 26)")
    dialect_counts: Counter = Counter()
    for r in log_rows:
        path = _resolve_evidence_path(r["file_path"])
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            non_empty = [l for l in lines if l.strip()]
            sample = non_empty[:3] if non_empty else []
            dialect = _detect_log_dialect(sample[0] if sample else "")
            dialect_counts[dialect] += 1
            print(f"    {r['file_id']:15s}  lines={len(non_empty):4d}  "
                  f"dialect={dialect:20s}  sample={repr(sample[0][:80]) if sample else 'empty'}")
        except Exception as exc:
            print(f"    {r['file_id']:15s}  ERROR: {exc}")
    print(f"  Dialect distribution: {dict(dialect_counts)}")


def _detect_log_dialect(line: str) -> str:
    """Classify a log line into one of the three known dialects."""
    if re.match(r"^<\d+>\d+\s+\d{4}-\d{2}-\d{2}T", line):
        return "syslog_rfc5424"
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*message=", line):
        return "cloud_runtime"
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line):
        return "key_value"
    return "unknown"


def inventory_pdf_files(manifest: list[dict[str, str]]) -> None:
    section("§2  PDF evidence files — text extraction")
    pdf_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".pdf"]
    print(f"  PDF files: {len(pdf_rows)} (expected 4)")
    try:
        import pypdf  # type: ignore
        for r in pdf_rows:
            path = _resolve_evidence_path(r["file_path"])
            try:
                reader = pypdf.PdfReader(str(path))
                pages = len(reader.pages)
                text = "\n".join(
                    page.extract_text() or "" for page in reader.pages
                )
                # look for user_ids, retention dates, resource refs
                user_refs = re.findall(r"\buser_\d+\b", text)
                resource_refs = re.findall(r"\b(?:account|audit_record|backup|export|support|tombstone|search)_\w+\b", text)
                retain_dates = re.findall(r"[Rr]etain until.*", text)
                print(f"    {r['file_id']:15s}  pages={pages}  "
                      f"text_len={len(text)}  "
                      f"user_refs={len(set(user_refs))}  "
                      f"resource_refs={len(set(resource_refs))}  "
                      f"retain_clauses={len(retain_dates)}")
            except Exception as exc:
                print(f"    {r['file_id']:15s}  ERROR: {exc}")
    except ImportError:
        print("  pypdf not installed — skipping PDF extraction")


def inventory_image_files(manifest: list[dict[str, str]]) -> None:
    section("§2  PNG evidence files — metadata")
    png_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".png"]
    print(f"  PNG files: {len(png_rows)} (expected 11)")
    try:
        from PIL import Image  # type: ignore
        for r in png_rows:
            path = _resolve_evidence_path(r["file_path"])
            try:
                img = Image.open(str(path))
                print(f"    {r['file_id']:15s}  size={img.size}  mode={img.mode}  "
                      f"format={img.format}  "
                      f"source={r.get('origin_system','?')}")
            except Exception as exc:
                print(f"    {r['file_id']:15s}  ERROR: {exc}")
    except ImportError:
        print("  Pillow not installed — skipping PNG metadata")


def inventory_txt_files(manifest: list[dict[str, str]]) -> None:
    section("§2  TXT evidence files")
    txt_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".txt"]
    print(f"  TXT files: {len(txt_rows)} (expected 1)")
    for r in txt_rows:
        path = _resolve_evidence_path(r["file_path"])
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            print(f"    {r['file_id']:15s}  size={len(text)}  "
                  f"lines={len(text.splitlines())}  preview={repr(text[:120])}")
        except Exception as exc:
            print(f"    {r['file_id']:15s}  ERROR: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# §3 — Hypothesis tests (H1–H7) using sample_output.csv
# ══════════════════════════════════════════════════════════════════════════════

def _load_sample_output() -> dict[str, dict]:
    """Load sample_output.csv → {case_id: {deletion_status, steps: list[dict]}}"""
    rows = read_csv(DATASET_DIR / "sample_output.csv")
    result = {}
    for r in rows:
        try:
            steps = json.loads(r["steps_json"])
        except Exception:
            steps = []
        result[r["case_id"]] = {"deletion_status": r["deletion_status"], "steps": steps}
    return result


def _load_sample_requests() -> list[dict[str, str]]:
    return read_csv(DATASET_DIR / "sample_deletion_requests.csv")


def _load_activity_by_case(
    activity: list[dict[str, str]],
    sample_requests: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    """Group activity rows by case_id using the request email and time window."""
    # Build email → case mapping from samples
    email_to_case: dict[str, str] = {}
    case_reported: dict[str, datetime] = {}
    for r in sample_requests:
        email_to_case[r["email"].strip().lower()] = r["case_id"]
        dt = parse_ts(r["reported_at"])
        if dt:
            case_reported[r["case_id"]] = dt

    # Also build user_id → case from identity + audit log
    id_rows = read_csv(DATASET_DIR / "user_identities.csv")
    email_uid: dict[str, str] = {
        r["email"].strip().lower(): r["user_id"] for r in id_rows
    }
    uid_to_case: dict[str, str] = {}
    for email, case_id in email_to_case.items():
        uid = email_uid.get(email)
        if uid:
            uid_to_case[uid] = case_id

    case_events: dict[str, list[dict[str, str]]] = defaultdict(list)
    for ev in activity:
        # Try matching by subject_email or subject_id in activity
        subj_email = ev.get("subject_email", "").strip().lower()
        subj_id = ev.get("subject_id", "").strip()
        case_id = email_to_case.get(subj_email) or uid_to_case.get(subj_id)
        if case_id:
            case_events[case_id].append(ev)
    return dict(case_events)


def test_h1_linking_window(
    sample_requests: list[dict[str, str]],
    sample_output: dict[str, dict],
    activity: list[dict[str, str]],
    manifest: list[dict[str, str]],
) -> None:
    """
    H1: Activity events for a case's expected resources fall within ~2 h of reported_at.
    We measure what fraction of expected resources have at least one activity event
    within the window.
    """
    section("H1 — Linking window (events within ±2 h of reported_at)")

    WINDOWS = [30 * 60, 60 * 60, 120 * 60, 240 * 60]  # seconds

    # Index activity by resource_id
    act_by_resource: dict[str, list[dict]] = defaultdict(list)
    for ev in activity:
        rid = ev.get("resource_id", "").strip()
        if rid:
            act_by_resource[rid].append(ev)

    window_hits: dict[int, int] = {w: 0 for w in WINDOWS}
    total_expected_resources = 0
    resources_with_any_activity = 0

    for r in sample_requests:
        case_id = r["case_id"]
        reported_dt = parse_ts(r["reported_at"])
        if not reported_dt:
            continue
        answer = sample_output.get(case_id, {})
        expected_resources = {s["resource_id"] for s in answer.get("steps", [])}
        total_expected_resources += len(expected_resources)

        for rid in expected_resources:
            events_for_rid = act_by_resource.get(rid, [])
            if events_for_rid:
                resources_with_any_activity += 1
            for w in WINDOWS:
                for ev in events_for_rid:
                    ev_dt = parse_ts(ev.get("event_time", ""))
                    if ev_dt and abs((ev_dt - reported_dt).total_seconds()) <= w:
                        window_hits[w] += 1
                        break  # one hit per resource per window size

    print(f"  Total expected resources across 32 samples: {total_expected_resources}")
    print(f"  Resources with ANY activity event: {resources_with_any_activity}")
    for w in WINDOWS:
        pct = 100 * window_hits[w] / max(total_expected_resources, 1)
        print(f"  Within ±{w//60:3d} min: {window_hits[w]:3d}/{total_expected_resources} = {pct:.1f}%")

    pct_2h = 100 * window_hits[120 * 60] / max(total_expected_resources, 1)
    if pct_2h >= 90:
        print(f"  H1 -> CONFIRMED  ({pct_2h:.1f}% within ±2 h)")
    elif pct_2h >= 50:
        print(f"  H1 -> PARTIAL    ({pct_2h:.1f}% within ±2 h)")
    else:
        print(f"  H1 -> REJECTED   ({pct_2h:.1f}% within ±2 h)")


def test_h2_anonymized_linking(
    sample_requests: list[dict[str, str]],
    sample_output: dict[str, dict],
    manifest: list[dict[str, str]],
    activity: list[dict[str, str]],
) -> None:
    """
    H2: Anonymized records are linked to a user only via activity events, catalog events,
    or other evidence — not via direct identifiers.
    """
    section("H2 — Anonymized record linking")

    # Find steps with ANONYMIZE / ANONYMIZED operations
    anon_resources: list[tuple[str, str]] = []  # (case_id, resource_id)
    for case_id, ans in sample_output.items():
        for s in ans.get("steps", []):
            if s.get("state") in ("ANONYMIZED",) or s.get("operation") in ("ANONYMIZE_RECORD",):
                anon_resources.append((case_id, s["resource_id"]))

    print(f"  Resources requiring ANONYMIZE in samples: {len(anon_resources)}")

    # For each, check if the evidence_id is an activity event vs a file
    act_ids = {r.get("activity_id", "") for r in activity if r.get("activity_id")}
    file_ids = {r["file_id"] for r in manifest}
    for case_id, rid in anon_resources[:10]:
        # Find the finding step's evidence
        ans = sample_output.get(case_id, {})
        eid = next(
            (s.get("evidence_id", "") for s in ans.get("steps", [])
             if s.get("resource_id") == rid and s.get("phase") == "FINDING"),
            ""
        )
        kind = "activity" if eid in act_ids else ("file" if eid in file_ids else "empty/other")
        print(f"    case={case_id}  rid={rid}  finding_evidence={eid}  kind={kind}")

    if anon_resources:
        print("  H2 -> PARTIAL (manual inspection needed; see above)")
    else:
        print("  H2 -> UNVERIFIABLE (no ANONYMIZE steps in samples)")


def test_h3_link_resource_identity(
    activity: list[dict[str, str]],
    sample_output: dict[str, dict],
) -> None:
    """
    H3: LINK_RESOURCE_IDENTITY events carry authoritative resource ownership.
    Check whether any expected resource_id appears in these events.
    """
    section("H3 — LINK_RESOURCE_IDENTITY event authority")
    link_events = [r for r in activity if r.get("event_type") == "LINK_RESOURCE_IDENTITY"]
    linked_resources = {r.get("resource_id", ""): r for r in link_events}
    print(f"  LINK_RESOURCE_IDENTITY events: {len(link_events)}")
    print(f"  Resource IDs in these events: {list(linked_resources.keys())[:12]}")

    expected_all = {s["resource_id"]
                    for ans in sample_output.values()
                    for s in ans.get("steps", [])}
    overlap = expected_all & set(linked_resources.keys())
    print(f"  Overlap with expected sample resources: {len(overlap)}: {list(overlap)[:8]}")
    if overlap:
        print("  H3 -> CONFIRMED  (LINK_RESOURCE_IDENTITY events name expected resources)")
    else:
        print("  H3 -> PARTIAL    (no direct overlap in samples — may apply to full dataset)")


def test_h4_retain_evidence(
    activity: list[dict[str, str]],
    manifest: list[dict[str, str]],
    sample_output: dict[str, dict],
) -> None:
    """
    H4: RETAIN_RECORD events and PDFs give retention evidence for audit records / legal holds.
    """
    section("H4 — Retention evidence (RETAIN_RECORD + PDFs)")
    retain_events = [r for r in activity if r.get("event_type") == "RETAIN_RECORD"]
    pdf_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".pdf"]
    print(f"  RETAIN_RECORD activity events: {len(retain_events)}")
    print(f"  PDF evidence files: {len(pdf_rows)}")

    # Expected VERIFY_RECORD_PRESENT steps (retained records)
    retain_steps = [
        (case_id, s)
        for case_id, ans in sample_output.items()
        for s in ans.get("steps", [])
        if s.get("operation") == "VERIFY_RECORD_PRESENT"
    ]
    print(f"  VERIFY_RECORD_PRESENT steps in samples: {len(retain_steps)}")
    for case_id, s in retain_steps[:5]:
        print(f"    case={case_id}  rid={s['resource_id']}  evidence={s.get('evidence_id','')}")

    if retain_events or pdf_rows:
        print("  H4 -> PARTIAL (RETAIN_RECORD events and/or PDFs present; "
              "must confirm they link to specific VERIFY_RECORD_PRESENT resources)")
    else:
        print("  H4 -> REJECTED (no RETAIN_RECORD events and no PDFs)")


def test_h5_prefix_categories(manifest: list[dict[str, str]], activity: list[dict[str, str]]) -> None:
    """
    H5: Prefix → category mapping for cache_, email_delivery_, marketing_,
    object_, legal_hold_.
    """
    section("H5 — Resource prefix → system_id / category (hypothesis prefixes)")
    hypothesis_prefixes = ["cache_", "email_delivery_", "marketing_", "object_", "legal_hold_"]

    # Search in activity for these resource_id prefixes
    for pfx in hypothesis_prefixes:
        events = [r for r in activity if r.get("resource_id", "").startswith(pfx)]
        target_systems = Counter(r.get("target_system", "") for r in events)
        event_types = Counter(r.get("event_type", "") for r in events)
        if events:
            print(f"  {pfx:25s}  events={len(events):3d}  "
                  f"target_systems={dict(target_systems)}  event_types={list(event_types.keys())[:4]}")
        else:
            print(f"  {pfx:25s}  NO events in system_activity")

    # Search in SQL evidence files
    sql_rows = [r for r in manifest if _resolve_evidence_path(r["file_path"]).suffix.lower() == ".sql"]
    prefix_in_sql: dict[str, list[str]] = defaultdict(list)
    for r in sql_rows:
        path = _resolve_evidence_path(r["file_path"])
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            for pfx in hypothesis_prefixes:
                if pfx in raw:
                    prefix_in_sql[pfx].append(r["file_id"])
        except Exception:
            pass
    for pfx, fids in prefix_in_sql.items():
        print(f"  {pfx:25s}  found in SQL files: {fids}")

    print("  H5 -> needs manual cross-reference; marked PARTIAL until confirmed per prefix")


def test_h6_content_linking(
    sample_output: dict[str, dict],
    manifest: list[dict[str, str]],
) -> None:
    """
    H6: Evidence is 'relevant' only via content links, never through the manifest alone.
    """
    section("H6 — Content linking (evidence not identifiable from manifest alone)")

    # manifest has file_id, file_path, origin_system, captured_at — no case or user column
    manifest_columns = list(manifest[0].keys()) if manifest else []
    print(f"  Manifest columns: {manifest_columns}")
    case_col = any("case" in c.lower() for c in manifest_columns)
    user_col = any("user" in c.lower() for c in manifest_columns)
    print(f"  Manifest has 'case' column: {case_col}")
    print(f"  Manifest has 'user' column: {user_col}")

    if not case_col and not user_col:
        print("  H6 -> CONFIRMED  (manifest has no case/user column; "
              "links must come from file contents)")
    else:
        print("  H6 -> REJECTED   (manifest contains case or user reference)")


def test_h7_replica_as_remaining(
    sample_output: dict[str, dict],
) -> None:
    """
    H7: A replica holding a record that the primary no longer has counts as a remaining record.
    Verified by case_05 in samples (system_id=account_service for a failover replica record).
    """
    section("H7 — Replica = remaining record (system_id = logical service)")
    # Evidence: case_05 has a finding/remaining record whose evidence comes from a replica,
    # but system_id = account_service (not the replica name).
    case05 = sample_output.get("case_05", {})
    if not case05:
        print("  case_05 not in sample output — cannot verify directly")
        print("  H7 -> UNVERIFIABLE with available data")
        return

    finding_steps = [
        s for s in case05.get("steps", [])
        if s.get("phase") == "FINDING"
    ]
    print(f"  case_05 finding steps ({len(finding_steps)}):")
    for s in finding_steps:
        print(f"    system_id={s.get('system_id')}  resource_id={s.get('resource_id')}  "
              f"evidence={s.get('evidence_id')}")

    account_service_findings = [
        s for s in finding_steps if s.get("system_id") == "account_service"
    ]
    if account_service_findings:
        print("  H7 -> CONFIRMED  (case_05 uses logical system_id 'account_service' "
              "even for replica evidence)")
    else:
        print("  H7 -> PARTIAL    (case_05 has findings but not from account_service)")


def build_link_type_table(
    sample_output: dict[str, dict],
    manifest: list[dict[str, str]],
    activity: list[dict[str, str]],
) -> None:
    """
    §1.8: For each sample expected resource, record where its identity link comes from.
    """
    section("§1.8  Case → expected-resource → link-type table (samples)")
    act_ids = {r.get("activity_id", "") for r in activity if r.get("activity_id")}
    audit_ids = set()  # audit_log ids
    try:
        for r in read_csv(DATASET_DIR / "user_audit_log.csv"):
            if r.get("audit_id"):
                audit_ids.add(r["audit_id"])
    except Exception:
        pass
    file_ids = {r["file_id"] for r in manifest}

    link_type_counter: Counter = Counter()
    for case_id, ans in sorted(sample_output.items()):
        for s in ans.get("steps", []):
            eid = s.get("evidence_id", "")
            if not eid:
                link_type = "empty(remediation/future-verify)"
            elif eid in act_ids:
                link_type = "activity_event"
            elif eid in audit_ids:
                link_type = "audit_log"
            elif eid in file_ids:
                link_type = "evidence_file"
            else:
                link_type = f"unknown:{eid[:15]}"
            link_type_counter[link_type] += 1

    print(f"  Evidence ID type distribution across all sample steps:")
    for lt, cnt in link_type_counter.most_common():
        print(f"    {lt:40s}: {cnt}")


def list_decoys(
    sample_requests: list[dict[str, str]],
    sample_output: dict[str, dict],
    manifest: list[dict[str, str]],
    activity: list[dict[str, str]],
) -> None:
    """§1.9: List decoy patterns."""
    section("§1.9  Decoy patterns")

    # Same resource_id prefix or name appearing in multiple cases
    resource_case_map: dict[str, set[str]] = defaultdict(set)
    for case_id, ans in sample_output.items():
        for s in ans.get("steps", []):
            resource_case_map[s["resource_id"]].add(case_id)
    multi_case_resources = {
        rid: cases
        for rid, cases in resource_case_map.items()
        if len(cases) > 1
    }
    print(f"  Resource IDs appearing in multiple sample cases: {len(multi_case_resources)}")
    for rid, cases in list(multi_case_resources.items())[:5]:
        print(f"    {rid} → {sorted(cases)}")

    # Shared names check
    id_rows = read_csv(DATASET_DIR / "user_identities.csv")
    name_map: dict[str, list[str]] = defaultdict(list)
    for r in id_rows:
        if r.get("name"):
            name_map[r["name"].strip()].append(r["user_id"])
    shared = {n: uids for n, uids in name_map.items() if len(uids) > 1}
    print(f"  Names shared by multiple users: {len(shared)}")
    for n, uids in list(shared.items())[:3]:
        print(f"    '{n}': {uids}")


def verify_sample_sort(sample_output: dict[str, dict]) -> None:
    section("§1.1  sample_output.csv — case_id sort order check")
    sample_ids = list(sample_output.keys())
    str_sorted = sorted(sample_ids, key=str)
    num_sorted = sorted(sample_ids, key=lambda x: int(x.split("_")[-1]))
    if sample_ids == str_sorted:
        ok("sample_output.csv is in plain STRING sort order → use CASE_ID_SORT_KEY=str")
    elif sample_ids == num_sorted:
        ok("sample_output.csv is in NUMERIC sort order → use CASE_ID_SORT_KEY=int")
    else:
        print(f"  sample_output.csv is NOT in either expected sort order")
        print(f"  First 5 ids: {sample_ids[:5]}")
        print(f"  str-sorted:  {str_sorted[:5]}")
        print(f"  num-sorted:  {num_sorted[:5]}")
        fail("Cannot determine case_id sort order from sample_output.csv")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print("\n" + "=" * 70)
    print("  Ghost Data Still Exists — Phase 1: Dataset Profiler")
    print("=" * 70)

    requests     = verify_requests()
    id_map       = verify_identities(requests)
    audit_rows   = verify_audit_log()
    activity     = verify_activity()
    rules        = verify_rules()
    manifest     = verify_evidence_manifest()

    # Evidence inventory
    inventory_sql_files(manifest)
    inventory_json_files(manifest)
    inventory_log_files(manifest)
    inventory_pdf_files(manifest)
    inventory_image_files(manifest)
    inventory_txt_files(manifest)

    # Hypothesis tests (dev-only: uses sample_output.csv)
    sample_output  = _load_sample_output()
    sample_reqs    = _load_sample_requests()
    verify_sample_sort(sample_output)

    test_h1_linking_window(sample_reqs, sample_output, activity, manifest)
    test_h2_anonymized_linking(sample_reqs, sample_output, manifest, activity)
    test_h3_link_resource_identity(activity, sample_output)
    test_h4_retain_evidence(activity, manifest, sample_output)
    test_h5_prefix_categories(manifest, activity)
    test_h6_content_linking(sample_output, manifest)
    test_h7_replica_as_remaining(sample_output)
    build_link_type_table(sample_output, manifest, activity)
    list_decoys(sample_reqs, sample_output, manifest, activity)

    # Final verdict
    section("RESULT")
    if REQUIRED_FAILURES:
        print(f"\n  REQUIRED INVARIANT FAILURES ({len(REQUIRED_FAILURES)}):")
        for f in REQUIRED_FAILURES:
            print(f"    * {f}")
        sys.exit(1)
    else:
        print("  All required invariants passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
