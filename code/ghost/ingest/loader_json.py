"""
loader_json.py — Loads JSON evidence files into normalized Observations and SnapshotCoverage.

Handles all 28 JSON evidence files across the 3 distinct shapes.
Produces SnapshotCoverage for every collection/scope inspected.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.models import Observation, SnapshotCoverage, UnparsedEvidenceRecord


def _parse_iso(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
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
        return None


def _infer_system_and_category(system_hint: str | None, collection_hint: str | None, resource_id: str) -> tuple[str, str | None]:
    s = (system_hint or "").lower()
    c = (collection_hint or "").lower()
    r = resource_id.lower()

    if r.startswith("account_") or "account" in s or "customer_profile" in c:
        return "account_service", "USER_PROFILE"
    if r.startswith("search_") or "search" in s or "search" in c:
        return "search_service", "SEARCH_INDEX_ENTRY"
    if r.startswith("analytics_") or "analytics" in s or "analytics" in c:
        return "analytics_platform", "ANALYTICS_PROFILE"
    if r.startswith("support_") or "support" in s or "ticket" in c:
        return "support_platform", "SUPPORT_MESSAGE"
    if r.startswith("export_") or "export" in s or "export" in c:
        return "export_service", "USER_EXPORT"
    if r.startswith("data_flow_") or "connector" in s or "connector" in c or "integration" in s:
        return "integration_service", None
    if r.startswith("backup_") or "backup" in s or "backup" in c:
        return "backup_service", "BACKUP_ARCHIVE"
    if r.startswith("audit_record_") or "security" in s or "audit" in c:
        return "security_service", "SECURITY_AUDIT_LOG"
    if r.startswith("tombstone_") or "deleted_customer" in c:
        return "identity_service", "ACCOUNT_TOMBSTONE"
    if r.startswith("legal_hold_") or "legal" in s:
        return "legal_service", "LEGAL_HOLD_RECORD"
    if r.startswith("object_"):
        return "object_storage", "SUPPORT_ATTACHMENT"
    if r.startswith("marketing_") or "marketing" in s:
        return "marketing_platform", "MARKETING_PROFILE"
    if r.startswith("cache_") or "cache" in s:
        return "cache_service", "CACHE_ENTRY"
    if r.startswith("email_delivery_") or "email_delivery" in s:
        return "email_delivery_service", "EMAIL_DELIVERY_LOG"

    return s or "unknown_service", None


def _normalize_record_fields(rec: dict[str, Any]) -> dict[str, Any]:
    fields = dict(rec)
    if "profile" in rec and isinstance(rec["profile"], dict):
        fields.update(rec["profile"])
    if "document" in rec and isinstance(rec["document"], dict):
        fields.update(rec["document"])

    uid = (
        fields.get("user_id")
        or fields.get("customer_reference")
        or fields.get("subject_reference")
    )
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

    phone = (
        fields.get("phone")
        or fields.get("owner_phone")
        or fields.get("requester_phone")
    )
    if phone:
        fields["phone"] = str(phone).strip()

    name = (
        fields.get("full_name")
        or fields.get("display_name")
        or fields.get("requester_name")
    )
    if name:
        fields["name"] = str(name).strip()

    return fields


def load_json_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[SnapshotCoverage], list[UnparsedEvidenceRecord]]:
    observations: list[Observation] = []
    coverages: list[SnapshotCoverage] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "JSON parse error", str(exc)))
        return observations, coverages, unparsed

    file_captured_at = manifest_captured_at

    # Shape 1: Snapshot bundles (data["snapshots"])
    if isinstance(data, dict) and "snapshots" in data and isinstance(data["snapshots"], list):
        for s_idx, snap in enumerate(data["snapshots"]):
            if not isinstance(snap, dict):
                continue
            collection = snap.get("collection", "default")
            data_store = snap.get("data_store", "export")
            records = snap.get("records", [])

            snap_rids: set[str] = set()
            snap_sys, _ = _infer_system_and_category(data_store, collection, "")

            for r_idx, rec in enumerate(records):
                if not isinstance(rec, dict):
                    continue
                rid = rec.get("resource_id") or f"{collection}_{r_idx}"
                snap_rids.add(rid)
                system_id, category = _infer_system_and_category(data_store, collection, rid)
                snap_sys = system_id
                fields = _normalize_record_fields(rec)
                obs_id = f"{file_id}:{collection}:{rid}:{r_idx}"

                observations.append(
                    Observation(
                        obs_id=obs_id,
                        file_id=file_id,
                        captured_at=file_captured_at,
                        system_id=system_id,
                        store=data_store,
                        resource_id=rid,
                        category=category,
                        fields=fields,
                        present=True,
                    )
                )

            coverages.append(
                SnapshotCoverage(
                    file_id=file_id,
                    captured_at=file_captured_at,
                    system_id=snap_sys,
                    store=data_store,
                    scope_name=collection,
                    resource_ids=frozenset(snap_rids),
                )
            )

    # Shape 2: Service resource exports (data["service_exports"])
    elif isinstance(data, dict) and "service_exports" in data and isinstance(data["service_exports"], dict):
        for svc_name, svc_data in data["service_exports"].items():
            if not isinstance(svc_data, dict):
                continue
            for coll_name, records in svc_data.items():
                if not isinstance(records, list):
                    continue
                coll_rids: set[str] = set()
                coll_sys, _ = _infer_system_and_category(svc_name, coll_name, "")

                for r_idx, rec in enumerate(records):
                    if not isinstance(rec, dict):
                        continue
                    rid = rec.get("resource_id") or f"{coll_name}_{r_idx}"
                    coll_rids.add(rid)
                    system_id, category = _infer_system_and_category(svc_name, coll_name, rid)
                    coll_sys = system_id
                    fields = _normalize_record_fields(rec)
                    rec_time = _parse_iso(rec.get("observed_at")) or file_captured_at
                    rec_status = rec.get("status_code") or rec.get("status")
                    present = not (rec_status == 404 or rec_status == "404" or rec_status == "ABSENT" or rec.get("profile") is None and "profile" in rec)
                    obs_id = f"{file_id}:{svc_name}:{coll_name}:{rid}:{r_idx}"

                    observations.append(
                        Observation(
                            obs_id=obs_id,
                            file_id=file_id,
                            captured_at=file_captured_at,
                            system_id=system_id,
                            store=svc_name,
                            resource_id=rid,
                            category=category,
                            fields=fields,
                            present=present,
                        )
                    )

                coverages.append(
                    SnapshotCoverage(
                        file_id=file_id,
                        captured_at=file_captured_at,
                        system_id=coll_sys,
                        store=svc_name,
                        scope_name=f"{svc_name}.{coll_name}",
                        resource_ids=frozenset(coll_rids),
                    )
                )

    # Shape 3: Single-collection exports (data["records"])
    elif isinstance(data, dict) and "records" in data and isinstance(data["records"], list):
        collection = data.get("collection") or data.get("source") or data.get("origin") or "records"
        rec_rids: set[str] = set()
        rec_sys = data.get("source") or data.get("origin") or "export_service"
        top_sys, _ = _infer_system_and_category(rec_sys, collection, "")

        for r_idx, rec in enumerate(data["records"]):
            if not isinstance(rec, dict):
                continue
            rid = rec.get("resource_id") or f"{collection}_{r_idx}"
            rec_rids.add(rid)
            item_sys = rec.get("system") or rec_sys
            system_id, category = _infer_system_and_category(item_sys, collection, rid)
            top_sys = system_id
            fields = _normalize_record_fields(rec)
            rec_time = _parse_iso(rec.get("recorded_at")) or file_captured_at
            obs_id = f"{file_id}:{collection}:{rid}:{r_idx}"

            observations.append(
                Observation(
                    obs_id=obs_id,
                    file_id=file_id,
                    captured_at=rec_time,
                    system_id=system_id,
                    store="export",
                    resource_id=rid,
                    category=category,
                    fields=fields,
                    present=True,
                )
            )

        coverages.append(
            SnapshotCoverage(
                file_id=file_id,
                captured_at=file_captured_at,
                system_id=top_sys,
                store="export",
                scope_name=collection,
                resource_ids=frozenset(rec_rids),
            )
        )

    else:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), f"Unknown JSON structure with keys: {list(data.keys())}"))

    return observations, coverages, unparsed
