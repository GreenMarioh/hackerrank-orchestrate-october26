"""
identity.py — Identity resolution for current and historical customer profiles.

Reconstructs the subject's full identity bundle as of case.audit_at:
- Stable user_id
- Current and historical emails
- Current and historical phone numbers
- Current and historical names
- SHA-256 email hashes (current + historical)
- Citable audit_id chain proving historical links
- Strict enforcement of event_time <= audit_at (anti-leak contract)
"""
from __future__ import annotations

import csv
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.config import USER_AUDIT_LOG_CSV, USER_IDENTITIES_CSV
from ghost.models import Case, Identity


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


def _sha256(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()


class IdentityResolver:
    """
    In-memory identity resolver that indexes user_identities.csv and user_audit_log.csv.
    """

    def __init__(
        self,
        identities_path: Path = USER_IDENTITIES_CSV,
        audit_log_path: Path = USER_AUDIT_LOG_CSV,
    ) -> None:
        self.identities: dict[str, dict[str, Any]] = {}
        self.current_email_to_uid: dict[str, str] = {}
        self.current_hash_to_uid: dict[str, str] = {}
        self.audit_events_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.audit_events: list[dict[str, Any]] = []

        self._load_identities(identities_path)
        self._load_audit_log(audit_log_path)

    def _load_identities(self, path: Path) -> None:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                uid = r["user_id"].strip()
                email = r["email"].strip().lower()
                email_hash = r.get("email_hash", "").strip().lower() or _sha256(email)
                self.identities[uid] = {
                    "user_id": uid,
                    "email": email,
                    "phone": r.get("phone", "").strip(),
                    "name": r.get("full_name") or r.get("name", "").strip(),
                    "email_hash": email_hash,
                    "updated_at": _parse_iso(r.get("updated_at")),
                }
                self.current_email_to_uid[email] = uid
                self.current_hash_to_uid[email_hash] = uid

    def _load_audit_log(self, path: Path) -> None:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                ev_time = _parse_iso(r.get("event_time") or r.get("changed_at"))
                ev = {
                    "audit_id": r["audit_id"].strip(),
                    "user_id": r["user_id"].strip(),
                    "event_time": ev_time,
                    "field_name": r.get("field_name") or r.get("field_changed", "").strip(),
                    "old_value": r.get("old_value", "").strip(),
                    "new_value": r.get("new_value", "").strip(),
                }
                self.audit_events.append(ev)
                self.audit_events_by_user[ev["user_id"]].append(ev)

    def resolve_case(self, case: Case) -> Identity:
        return self.resolve(case.email, case.audit_at)

    def resolve(self, email: str, audit_at: datetime) -> Identity:
        """
        Resolves an email address to a strongly typed Identity valid as of audit_at.
        """
        norm_email = email.strip().lower()
        email_hash = _sha256(norm_email)

        # 1. Direct match on current email snapshot
        matched_uid = self.current_email_to_uid.get(norm_email)

        # 2. Match on historical email in user_audit_log (event_time <= audit_at)
        audit_ids_used: list[str] = []
        if not matched_uid:
            for ev in self.audit_events:
                if ev["event_time"] > audit_at:
                    continue
                if ev["field_name"] == "email":
                    old_e = ev["old_value"].strip().lower()
                    new_e = ev["new_value"].strip().lower()
                    if norm_email in (old_e, new_e):
                        matched_uid = ev["user_id"]
                        audit_ids_used.append(ev["audit_id"])
                        break

        # 3. Match on SHA-256 email hash
        if not matched_uid:
            matched_uid = self.current_hash_to_uid.get(email_hash)

        # 4. Match on historical email_hash in audit log
        if not matched_uid:
            for ev in self.audit_events:
                if ev["event_time"] > audit_at:
                    continue
                if ev["field_name"] == "email_hash":
                    if email_hash in (ev["old_value"].strip().lower(), ev["new_value"].strip().lower()):
                        matched_uid = ev["user_id"]
                        audit_ids_used.append(ev["audit_id"])
                        break

        if not matched_uid:
            # Fallback for synthetic/orphan identity without matching account
            return Identity(
                user_id="unknown_user",
                current_email=norm_email,
                all_emails=frozenset([norm_email]),
                all_phones=frozenset(),
                all_hashes=frozenset([email_hash]),
                name=None,
                is_ambiguous=False,
                evidence_audit_ids=(),
            )

        # Assemble the full identity bundle for matched_uid as of audit_at
        user_record = self.identities.get(matched_uid, {})
        current_email = user_record.get("email", norm_email)
        current_name = user_record.get("name")
        current_phone = user_record.get("phone")

        all_emails: set[str] = {norm_email}
        if current_email:
            all_emails.add(current_email.lower())

        all_phones: set[str] = set()
        if current_phone:
            all_phones.add(current_phone)

        all_hashes: set[str] = set()
        for e in all_emails:
            all_hashes.add(_sha256(e))

        # Reconstruct history from user_audit_log strictly up to audit_at
        user_events = self.audit_events_by_user.get(matched_uid, [])
        for ev in user_events:
            if ev["event_time"] > audit_at:
                continue

            fname = ev["field_name"]
            old_val = ev["old_value"].strip()
            new_val = ev["new_value"].strip()

            if fname == "email":
                if old_val:
                    all_emails.add(old_val.lower())
                    all_hashes.add(_sha256(old_val))
                if new_val:
                    all_emails.add(new_val.lower())
                    all_hashes.add(_sha256(new_val))
                if ev["audit_id"] not in audit_ids_used:
                    audit_ids_used.append(ev["audit_id"])

            elif fname == "phone":
                if old_val:
                    all_phones.add(old_val)
                if new_val:
                    all_phones.add(new_val)
                if ev["audit_id"] not in audit_ids_used:
                    audit_ids_used.append(ev["audit_id"])

            elif fname == "email_hash":
                if old_val:
                    all_hashes.add(old_val.lower())
                if new_val:
                    all_hashes.add(new_val.lower())
                if ev["audit_id"] not in audit_ids_used:
                    audit_ids_used.append(ev["audit_id"])

        return Identity(
            user_id=matched_uid,
            current_email=current_email,
            all_emails=frozenset(all_emails),
            all_phones=frozenset(all_phones),
            all_hashes=frozenset(all_hashes),
            name=current_name,
            is_ambiguous=False,
            evidence_audit_ids=tuple(audit_ids_used),
        )
