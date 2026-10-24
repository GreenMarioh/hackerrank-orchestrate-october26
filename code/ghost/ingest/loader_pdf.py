"""
loader_pdf.py — Loads PDF evidence documents into normalized Observations.

Uses pure Python pypdf (no poppler / tesseract required).
Extracts user IDs, emails, phones, resource IDs, and retain-until dates.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pypdf

from ghost.models import Observation, UnparsedEvidenceRecord


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


def _infer_system(resource_id: str, title_hint: str) -> str:
    r = resource_id.lower()
    t = title_hint.lower()
    if r.startswith("account_") or "statement" in t or "account" in t:
        return "account_service"
    if r.startswith("support_") or "delivery address" in t or "support" in t:
        return "support_platform"
    if r.startswith("audit_record_") or "compliance" in t or "security" in t:
        return "security_service"
    if r.startswith("legal_hold_") or "dispute" in t or "tax" in t or "legal" in t:
        return "legal_service"
    return "document_service"


def load_pdf_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[UnparsedEvidenceRecord]]:
    observations: list[Observation] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    try:
        reader = pypdf.PdfReader(str(file_path))
        full_text = "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "PDF read error", str(exc)))
        return observations, unparsed

    if not full_text.strip():
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "Empty PDF extracted text"))
        return observations, unparsed

    # Extract all resource references: e.g. support_001, audit_record_003, account_...
    resource_matches = list(set(re.findall(
        r"\b(account_\w+|search_\w+|support_\w+|analytics_\w+|export_\w+|data_flow_\w+|backup_\w+|audit_record_\w+|tombstone_\w+|object_\w+|marketing_\w+|legal_hold_\w+)\b",
        full_text,
    )))

    # Extract user IDs, emails, phones
    user_ids = list(set(re.findall(r"\buser_\d+\b", full_text)))
    emails = list(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", full_text)))
    phones = list(set(re.findall(r"\+\d{1,3}[\s-]?\d{1,4}[\s-]?\d{3,5}[\s-]?\d{3,5}", full_text)))
    retain_matches = re.findall(r"[Rr]etain until\s+([^\n.]+)", full_text)

    # If resources were matched, create one observation per resource
    if resource_matches:
        for idx, rid in enumerate(resource_matches):
            system_id = _infer_system(rid, full_text[:200])
            fields: dict[str, Any] = {
                "source_text": full_text[:500],
                "matched_resources": resource_matches,
                "all_user_ids": user_ids,
                "all_emails": [e.lower() for e in emails],
                "all_phones": phones,
            }
            if user_ids:
                fields["user_id"] = user_ids[0]
            if emails:
                fields["email"] = emails[0].lower()
            if phones:
                fields["phone"] = phones[0]
            if retain_matches:
                fields["retain_until"] = retain_matches[0].strip()

            obs_id = f"{file_id}:doc:{rid}:{idx}"
            observations.append(
                Observation(
                    obs_id=obs_id,
                    file_id=file_id,
                    captured_at=manifest_captured_at,
                    system_id=system_id,
                    store="doc",
                    resource_id=rid,
                    category=None,
                    fields=fields,
                    present=True,
                )
            )

    # If no explicit resource_id matched but user identifiers exist (e.g. statement or register rows)
    elif user_ids or emails:
        for idx, uid in enumerate(user_ids or [None]):
            rid = f"doc_{file_id}_{idx}"
            system_id = _infer_system(rid, full_text[:200])
            fields = {
                "all_user_ids": user_ids,
                "all_emails": [e.lower() for e in emails],
                "all_phones": phones,
            }
            if uid:
                fields["user_id"] = uid
            if emails:
                fields["email"] = emails[0].lower()
            if phones:
                fields["phone"] = phones[0]
            if retain_matches:
                fields["retain_until"] = retain_matches[0].strip()

            obs_id = f"{file_id}:doc:{rid}:{idx}"
            observations.append(
                Observation(
                    obs_id=obs_id,
                    file_id=file_id,
                    captured_at=manifest_captured_at,
                    system_id=system_id,
                    store="doc",
                    resource_id=rid,
                    category=None,
                    fields=fields,
                    present=True,
                )
            )

    else:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "No user IDs or resources found in PDF text"))

    return observations, unparsed
