"""
loader_txt.py — Loads plain text evidence files into normalized Observations.

Handles evidence_03 (customer_account_handover_20261001.txt) with pipe-delimited check results.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def load_txt_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[UnparsedEvidenceRecord]]:
    observations: list[Observation] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "TXT read error", str(exc)))
        return observations, unparsed

    file_ts = manifest_captured_at
    for line in lines[:10]:
        if "snapshot:" in line.lower():
            m = re.search(r"snapshot:\s*([^\s]+)", line, re.IGNORECASE)
            if m:
                parsed = _parse_iso(m.group(1))
                if parsed:
                    file_ts = parsed
                    break

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or not line.startswith("-"):
            continue

        # Format: - TIMESTAMP | SYSTEM_ID | RESOURCE_ID | CATEGORY | STATUS | IDENTIFIER
        content = line.lstrip("-").strip()
        parts = [p.strip() for p in content.split("|")]
        if len(parts) >= 6:
            row_time = _parse_iso(parts[0]) or file_ts
            system_id = parts[1]
            resource_id = parts[2]
            category = parts[3]
            status = parts[4].upper()
            identifier = parts[5]

            fields: dict[str, Any] = {
                "status": status,
                "raw_identifier": identifier,
            }

            if "@" in identifier:
                fields["email"] = identifier.lower()
            elif identifier.startswith("user_"):
                fields["user_id"] = identifier

            # Present flag: if status is NOT_FOUND or ABSENT, present=False
            present = status not in ("NOT_FOUND", "ABSENT")
            if status in ("BLOCKED", "DISABLED"):
                if "backup" in system_id or resource_id.startswith("backup_"):
                    fields["restore_allowed"] = False
                if "integration" in system_id or resource_id.startswith("data_flow_"):
                    fields["enabled"] = False
            elif status == "ACTIVE":
                if "backup" in system_id or resource_id.startswith("backup_"):
                    fields["restore_allowed"] = True
                if "integration" in system_id or resource_id.startswith("data_flow_"):
                    fields["enabled"] = True

            obs_id = f"{file_id}:line_{idx}:{resource_id}"
            observations.append(
                Observation(
                    obs_id=obs_id,
                    file_id=file_id,
                    captured_at=row_time,
                    system_id=system_id,
                    store="doc",
                    resource_id=resource_id,
                    category=category,
                    fields=fields,
                    present=present,
                )
            )

    if not observations and not unparsed:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "Zero lines parsed from TXT file"))

    return observations, unparsed
