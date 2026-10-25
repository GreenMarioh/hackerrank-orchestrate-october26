"""
loader_logs.py — Loads log evidence files into normalized Observations.

Supports all 3 dialects:
1. key_value
2. cloud_runtime (with message= field and escaped quotes)
3. syslog_rfc5424 (with optional prepended ISO ingestion timestamp)
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.models import Observation, UnparsedEvidenceRecord

KNOWN_SERVICES: set[str] = {
    "account_service", "search_service", "analytics_platform", "support_platform",
    "security_service", "backup_service", "export_service", "integration_service",
    "legal_service", "identity_service", "email_delivery_service", "marketing_platform",
    "cache_service", "object_storage", "document_service", "log_service",
}

EVENT_NAMES: set[str] = {
    "analytics_identity_scan", "analytics_profile_scan_started", "attachment_pii_scan",
    "attachment_scan_started", "audit_record_query_started", "audit_record_read_completed",
    "cache_lookup", "cache_refresh", "connection_acquired", "connector_config_read_started",
    "connector_heartbeat", "consumer_lag", "contact_lookup_completed", "delivery_abandoned",
    "dependency_recovered", "dependency_retry", "export_completed", "export_download_check_completed",
    "export_download_check_started", "export_started", "index_query_completed", "index_query_started",
    "lease_extended", "message_pii_scan", "message_scan_started", "profile_lookup_completed",
    "profile_lookup_started", "restore_candidate_evaluated", "restore_policy_check_started",
}


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


def _parse_key_value(line: str) -> dict[str, str]:
    result: dict[str, str] = {}

    # If line contains a JSON payload (e.g. ISO-timestamp {"severity":...})
    brace_start = line.find("{")
    brace_end = line.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        try:
            payload = json.loads(line[brace_start:brace_end + 1])
            if isinstance(payload, dict):
                for pk, pv in payload.items():
                    if pv is not None:
                        result[str(pk)] = str(pv)
        except Exception:
            pass

    pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s,]+)')
    for m in pattern.finditer(line):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        if k not in result:
            result[k] = v

    # If line is pipe-delimited, extract positional tokens: ts | level | service | trace_id | event | kv...
    if "|" in line:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4:
            if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", parts[0]) and "timestamp" not in result:
                result["timestamp"] = parts[0]
            if parts[1] in ("DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL") and "level" not in result:
                result["level"] = parts[1]
            if "service" not in result and not "=" in parts[2]:
                result["service"] = parts[2]
            if parts[3].startswith("tr-") and "trace_id" not in result:
                result["trace_id"] = parts[3]
            if len(parts) >= 5 and "event" not in result and not "=" in parts[4]:
                result["event"] = parts[4]

    # Extract bracketed positional tokens: [LEVEL] [service] [trace_id]
    brackets = re.findall(r"\[([^\]]+)\]", line)
    for b in brackets:
        if b in ("DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL") and "level" not in result:
            result["level"] = b
        elif b.startswith("tr-") and "trace_id" not in result:
            result["trace_id"] = b
        elif ("service" in b or "platform" in b) and "service" not in result:
            result["service"] = b

    return result


def _parse_syslog_rfc5424(line: str) -> dict[str, str]:
    # Handles optional prepended ISO ingestion timestamp
    pattern = re.compile(
        r"^(?:\S+T\S+\s+)?"
        r"<(\d+)>(\d+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(?:\[.*?\]\s*)?"
        r"(.*)?$",
        re.DOTALL,
    )
    m = pattern.match(line)
    if not m:
        return _parse_key_value(line)
    fields = {
        "priority": m.group(1),
        "version": m.group(2),
        "timestamp": m.group(3),
        "hostname": m.group(4),
        "app_name": m.group(5),
        "proc_id": m.group(6),
        "msg_id": m.group(7),
        "message": (m.group(8) or "").strip(),
    }
    if fields.get("app_name", "").startswith("tr-"):
        fields["trace_id"] = fields["app_name"]
    if "service" not in fields and fields.get("hostname"):
        fields["service"] = fields["hostname"]

    # Also parse any key=value inside the message
    msg = fields["message"]
    if msg:
        kv = _parse_key_value(msg)
        fields.update(kv)
    return fields


def _parse_cloud_runtime(line: str) -> dict[str, str]:
    return _parse_key_value(line)


def _detect_dialect(line: str) -> str:
    if re.match(r"^(?:\S+T\S+\s+)?<\d+>\d+\s+", line):
        return "syslog_rfc5424"
    has_ts = bool(
        re.match(r"^timestamp=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)
        or re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)
    )
    if has_ts and "message=" in line:
        return "cloud_runtime"
    if has_ts:
        return "key_value"
    return "unknown"


def _infer_system(service_hint: str | None, resource_id: str) -> str:
    s = (service_hint or "").lower()
    r = resource_id.lower()
    if r.startswith("account_") or "account" in s:
        return "account_service"
    if r.startswith("search_") or "search" in s:
        return "search_service"
    if r.startswith("analytics_") or "analytics" in s:
        return "analytics_platform"
    if r.startswith("support_") or "support" in s:
        return "support_platform"
    if r.startswith("export_") or "export" in s:
        return "export_service"
    if r.startswith("data_flow_") or "integration" in s or "connector" in s:
        return "integration_service"
    if r.startswith("backup_") or "backup" in s:
        return "backup_service"
    if r.startswith("audit_record_") or "security" in s:
        return "security_service"
    if r.startswith("tombstone_") or "identity" in s:
        return "identity_service"
    if r.startswith("object_") or "storage" in s:
        return "object_storage"
    if r.startswith("marketing_") or "marketing" in s:
        return "marketing_platform"
    if r.startswith("cache_") or "cache" in s:
        return "cache_service"
    if r.startswith("email_delivery_") or "email_delivery" in s:
        return "email_delivery_service"
    if r.startswith("legal_hold_") or "legal" in s:
        return "legal_service"
    return s or "log_service"


def load_log_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[UnparsedEvidenceRecord]]:
    observations: list[Observation] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "Log file read error", str(exc)))
        return observations, unparsed

    # First pass: parse lines and index trace_id -> resource_id / identifiers
    parsed_lines = []
    trace_to_rid: dict[str, str] = {}
    trace_to_uid: dict[str, str] = {}
    trace_to_email: dict[str, str] = {}

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        dialect = _detect_dialect(line)
        if dialect == "syslog_rfc5424":
            parsed = _parse_syslog_rfc5424(line)
        elif dialect == "cloud_runtime":
            parsed = _parse_cloud_runtime(line)
        else:
            parsed = _parse_key_value(line)

        # Detect resource_id
        rid = parsed.get("resource_id")
        if not rid:
            for m in re.finditer(
                r"\b(account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|object|marketing|cache|email_delivery|legal_hold)_(\d+)\b",
                line,
            ):
                candidate = m.group(0)
                if candidate not in KNOWN_SERVICES and candidate not in EVENT_NAMES:
                    rid = candidate
                    break

        tr = parsed.get("trace_id")
        if tr:
            if rid:
                trace_to_rid[tr] = rid
            uid = parsed.get("user_id") or parsed.get("customer_reference") or parsed.get("subject_reference") or parsed.get("subject_ref") or parsed.get("correlation_key")
            if uid:
                trace_to_uid[tr] = str(uid).strip()
            email = (
                parsed.get("email")
                or parsed.get("lookup_key")
                or parsed.get("subject_key")
                or parsed.get("customer_email")
                or parsed.get("owner_email")
            )
            if email and "@" in str(email):
                trace_to_email[tr] = str(email).strip().lower()

        parsed_lines.append((idx, line, parsed, rid))

    for idx, line, parsed, rid in parsed_lines:
        tr = parsed.get("trace_id")
        if not rid and tr and tr in trace_to_rid:
            rid = trace_to_rid[tr]

        # Extract timestamp
        ts = None
        for t_key in ("timestamp", "time", "date"):
            if t_key in parsed:
                ts = _parse_iso(parsed[t_key])
                if ts:
                    break
        if not ts:
            # Check if line starts with an ISO timestamp
            m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", line)
            if m:
                ts = _parse_iso(m.group(1))
        if not ts:
            ts = manifest_captured_at

        # Extract user identifiers
        uid = (
            parsed.get("user_id")
            or parsed.get("customer_reference")
            or parsed.get("subject_reference")
            or parsed.get("subject_ref")
            or parsed.get("subject_id")
            or parsed.get("correlation_key")
            or (trace_to_uid.get(tr) if tr else None)
        )
        email = (
            parsed.get("email")
            or parsed.get("owner_email")
            or parsed.get("customer_email")
            or parsed.get("subject_email")
            or parsed.get("lookup_key")
            or parsed.get("subject_key")
            or (trace_to_email.get(tr) if tr else None)
        )
        phone = parsed.get("phone") or parsed.get("owner_phone")

        if not rid and not uid and not email:
            # Line has no personal data or resource reference (e.g. system heartbeat)
            continue

        if not rid:
            rid = f"log_entry_{file_id}_{idx}"

        system_id = parsed.get("system") or _infer_system(parsed.get("service") or parsed.get("app_name") or parsed.get("function"), rid)

        fields: dict[str, Any] = dict(parsed)
        if uid:
            uid_str = str(uid).strip()
            if uid_str.startswith("user_"):
                fields["user_id"] = uid_str
                fields["subject_reference"] = uid_str
            elif "@" in uid_str:
                fields["email"] = uid_str.lower()
            else:
                fields["user_id"] = uid_str
        if email:
            email_str = str(email).strip().lower()
            if "@" in email_str:
                fields["email"] = email_str
            elif email_str.startswith("user_"):
                fields["user_id"] = email_str
                fields["subject_reference"] = email_str
        if phone:
            fields["phone"] = str(phone).strip()

        # Handle record_lookup and profile_lookup event results
        category = parsed.get("record_type")
        result_val = str(parsed.get("result", "")).strip().upper()
        http_status = str(parsed.get("http_status", "")).strip()
        rows_val = str(parsed.get("rows", "")).strip()
        event_name = str(parsed.get("event", "")).strip()

        if result_val == "NOT_FOUND" or http_status == "404" or (rows_val == "0" and "completed" in event_name):
            present = False
        else:
            present = True

        obs_id = f"{file_id}:line_{idx}:{rid}"
        observations.append(
            Observation(
                obs_id=obs_id,
                file_id=file_id,
                captured_at=ts,
                file_captured_at=manifest_captured_at,
                system_id=system_id,
                store="log",
                resource_id=rid,
                category=category,
                fields=fields,
                present=present,
            )
        )

    if not observations and not unparsed:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "Zero observation lines extracted from log file"))

    return observations, unparsed
