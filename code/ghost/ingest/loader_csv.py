"""
loader_csv.py — Loads dataset CSV files into strongly typed models and Observations.

Parses:
- evidence_files.csv (manifest)
- deletion_requests.csv (cases)
- user_identities.csv (current snapshots)
- user_audit_log.csv (identity audit log Observations)
- system_activity.csv (operational activity Observations)
- deletion_rules.csv (policy rules)
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.config import (
    DELETION_REQUESTS_CSV,
    DELETION_RULES_CSV,
    EVIDENCE_FILES_CSV,
    SYSTEM_ACTIVITY_CSV,
    USER_AUDIT_LOG_CSV,
    USER_IDENTITIES_CSV,
)
from ghost.models import Case, Observation


def _parse_iso(ts_str: str | None) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    s = str(ts_str).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def load_manifest(path: Path = EVIDENCE_FILES_CSV) -> list[dict[str, Any]]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["captured_at_dt"] = _parse_iso(r["captured_at"])
    return rows


def load_deletion_requests(path: Path = DELETION_REQUESTS_CSV) -> list[Case]:
    cases = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            cases.append(
                Case(
                    case_id=r["case_id"].strip(),
                    email=r["email"].strip().lower(),
                    requested_at=_parse_iso(r["requested_at"]),
                    reported_status=r["reported_status"].strip().upper(),
                    reported_at=_parse_iso(r["reported_at"]),
                    audit_at=_parse_iso(r["audit_at"]),
                    request_text=r["request_text"].strip(),
                )
            )
    return cases


def load_activity_observations(path: Path = SYSTEM_ACTIVITY_CSV) -> list[Observation]:
    observations = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            aid = r["activity_id"].strip()
            ev_time = _parse_iso(r["event_time"])
            ev_type = r.get("event_type", "").strip()
            target_sys = r.get("target_system", "").strip()
            rid = r.get("resource_id", "").strip() or aid
            result = r.get("reported_result", "").strip()

            fields: dict[str, Any] = {
                "event_type": ev_type,
                "source_system": r.get("source_system", "").strip(),
                "target_system": target_sys,
                "reported_result": result,
                "details": r.get("details", "").strip(),
            }

            if r.get("subject_id"):
                fields["user_id"] = r["subject_id"].strip()
            if r.get("subject_email"):
                fields["email"] = r["subject_email"].strip().lower()

            observations.append(
                Observation(
                    obs_id=f"activity:{aid}:{rid}",
                    file_id=aid,
                    captured_at=ev_time,
                    system_id=target_sys or "activity_service",
                    store="activity",
                    resource_id=rid,
                    category=None,
                    fields=fields,
                    present=result != "FAILED",
                )
            )
    return observations


def load_audit_log_observations(path: Path = USER_AUDIT_LOG_CSV) -> list[Observation]:
    observations = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            audit_id = r["audit_id"].strip()
            ev_time = _parse_iso(r["changed_at"])
            uid = r.get("user_id", "").strip()
            field_name = r.get("field_changed", "").strip()

            fields: dict[str, Any] = {
                "user_id": uid,
                "field_changed": field_name,
                "old_value": r.get("old_value", "").strip(),
                "new_value": r.get("new_value", "").strip(),
                "actor": r.get("actor", "").strip(),
            }
            if field_name == "email":
                if r.get("new_value"):
                    fields["email"] = r["new_value"].strip().lower()
            elif field_name == "phone":
                if r.get("new_value"):
                    fields["phone"] = r["new_value"].strip()

            observations.append(
                Observation(
                    obs_id=f"audit:{audit_id}:{uid}",
                    file_id=audit_id,
                    captured_at=ev_time,
                    system_id="security_service",
                    store="audit",
                    resource_id=f"audit_log_{audit_id}",
                    category="SECURITY_AUDIT_LOG",
                    fields=fields,
                    present=True,
                )
            )
    return observations
