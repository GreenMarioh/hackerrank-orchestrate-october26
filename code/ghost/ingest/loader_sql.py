"""
loader_sql.py — Loads SQL snapshot evidence files into normalized Observations and SnapshotCoverage.

Parses table schemas and rows using in-memory sqlite3.
Handles all 24 SQL evidence files across Family A (account replicas) and Family B (multi-service).
Produces SnapshotCoverage for every table (including zero-row snapshots like evidence_90).
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.models import Observation, SnapshotCoverage, UnparsedEvidenceRecord


def _parse_iso(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    s = ts_str.strip()
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
        return None


def _detect_store_type(table_name: str, header_text: str) -> str:
    t_low = table_name.lower()
    h_low = header_text.lower()
    if "failover" in t_low or "failover" in h_low:
        return "failover_replica"
    if "regional" in t_low or "replica_ap" in t_low or "replica_eu" in t_low or "regional" in h_low:
        return "regional_replica"
    if "reporting" in t_low or "reporting" in h_low:
        return "reporting_replica"
    if "read_replica" in t_low or "read replica" in h_low:
        return "read_replica"
    return "primary"


def _infer_system_and_category(table_name: str, resource_id: str) -> tuple[str, str | None]:
    t = table_name.lower()
    r = resource_id.lower()
    if r.startswith("account_"):
        return "account_service", "USER_PROFILE"
    if r.startswith("search_") or "search" in t:
        return "search_service", "SEARCH_INDEX_ENTRY"
    if r.startswith("analytics_") or "analytics" in t:
        return "analytics_platform", "ANALYTICS_PROFILE"
    if r.startswith("support_") or "support" in t:
        return "support_platform", "SUPPORT_MESSAGE"
    if r.startswith("export_") or "export" in t:
        return "export_service", "USER_EXPORT"
    if r.startswith("data_flow_") or "connector" in t:
        return "integration_service", None
    if r.startswith("backup_") or "backup" in t:
        return "backup_service", "BACKUP_ARCHIVE"
    if r.startswith("audit_record_") or "security_audit" in t:
        return "security_service", "SECURITY_AUDIT_LOG"
    if r.startswith("tombstone_"):
        return "identity_service", "ACCOUNT_TOMBSTONE"
    if r.startswith("legal_hold_") or "legal" in t:
        return "legal_service", "LEGAL_HOLD_RECORD"
    if r.startswith("object_"):
        return "object_storage", "SUPPORT_ATTACHMENT"
    if r.startswith("marketing_") or "marketing" in t:
        return "marketing_platform", "MARKETING_PROFILE"
    if r.startswith("cache_") or "cache" in t:
        return "cache_service", "CACHE_ENTRY"
    if r.startswith("email_delivery_") or "email_delivery" in t:
        return "email_delivery_service", "EMAIL_DELIVERY_LOG"
    if "customer_profile" in t or "customer_data" in t:
        return "account_service", "USER_PROFILE"
    return "unknown_service", None


def load_sql_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[SnapshotCoverage], list[UnparsedEvidenceRecord]]:
    """
    Parses a single SQL file using sqlite3 in-memory and returns Observations and SnapshotCoverage.
    """
    observations: list[Observation] = []
    coverages: list[SnapshotCoverage] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "File read error", str(exc)))
        return observations, coverages, unparsed

    # Extract capture timestamp from header if present
    captured_at = manifest_captured_at
    header_comment = ""
    for line in content.splitlines()[:20]:
        if line.startswith("--"):
            header_comment += line + "\n"
            m = re.search(r"captured\s+at:\s*([^\s;]+)", line, re.IGNORECASE)
            if m:
                parsed_dt = _parse_iso(m.group(1))
                if parsed_dt:
                    captured_at = parsed_dt

    try:
        conn = sqlite3.connect(":memory:")
        conn.executescript(content)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        tables_query = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [r["name"] for r in tables_query]

        if not table_names:
            unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "No tables found in SQL file"))
            conn.close()
            return observations, coverages, unparsed

        for tbl in table_names:
            if tbl.lower() == "snapshot_scope":
                continue

            store_type = _detect_store_type(tbl, header_comment)
            rows = cur.execute(f'SELECT * FROM "{tbl}"').fetchall()

            table_rids: set[str] = set()
            tbl_system_id, _ = _infer_system_and_category(tbl, "")

            for idx, row in enumerate(rows):
                row_dict = dict(row)
                resource_id = row_dict.get("resource_id") or row_dict.get("id") or f"{tbl}_{idx}"
                resource_id = str(resource_id).strip()
                table_rids.add(resource_id)

                system_id, category = _infer_system_and_category(tbl, resource_id)
                tbl_system_id = system_id

                # Parse row-level capture/update time if available
                row_time = captured_at
                for t_col in ("captured_at", "updated_at", "created_at", "indexed_at"):
                    if t_col in row_dict and row_dict[t_col]:
                        parsed = _parse_iso(str(row_dict[t_col]))
                        if parsed:
                            row_time = parsed
                            break

                # Normalize fields dictionary
                fields: dict[str, Any] = {}
                for k, v in row_dict.items():
                    if k in ("record_json", "details_json", "data_json") and v:
                        try:
                            nested = json.loads(v)
                            if isinstance(nested, dict):
                                fields.update(nested)
                        except Exception:
                            fields[k] = v
                    else:
                        fields[k] = v

                # Unify common identity identifiers into standard field keys
                uid = fields.get("user_id") or fields.get("customer_reference") or fields.get("subject_reference")
                if uid:
                    fields["user_id"] = str(uid).strip()

                email = (
                    fields.get("email")
                    or fields.get("owner_email")
                    or fields.get("customer_email")
                    or fields.get("requester_email")
                )
                if email:
                    fields["email"] = str(email).strip().lower()

                phone = fields.get("phone") or fields.get("owner_phone") or fields.get("requester_phone")
                if phone:
                    fields["phone"] = str(phone).strip()

                name = fields.get("full_name") or fields.get("display_name") or fields.get("requester_name")
                if name:
                    fields["name"] = str(name).strip()

                obs_id = f"{file_id}:{tbl}:{resource_id}:{idx}"
                obs = Observation(
                    obs_id=obs_id,
                    file_id=file_id,
                    captured_at=row_time,
                    system_id=system_id,
                    store=store_type,
                    resource_id=resource_id,
                    category=category,
                    fields=fields,
                    present=True,
                )
                observations.append(obs)

            # Record SnapshotCoverage for this table (even if table_rids is empty, e.g. evidence_90)
            coverages.append(
                SnapshotCoverage(
                    file_id=file_id,
                    captured_at=captured_at,
                    system_id=tbl_system_id,
                    store=store_type,
                    scope_name=tbl,
                    resource_ids=frozenset(table_rids),
                )
            )

        conn.close()

    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "SQL execution error", str(exc)))

    return observations, coverages, unparsed
