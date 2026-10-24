"""
models.py — Data models for Ghost Data Still Exists.

All models are strongly-typed dataclasses.
Observation is immutable (frozen=True) to ensure determinism and prevent mutation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Observation:
    """
    Normalized observation extracted from evidence files, activity logs, or audit records.
    """
    obs_id: str            # deterministic: f"{file_id}:{table_or_path}:{resource_id}:{idx}"
    file_id: str           # evidence_NN | activity_NN | audit_NN
    captured_at: datetime  # timestamp of the observation (UTC)
    system_id: str         # logical service (account_service, search_service, ...)
    store: str             # primary | regional_replica | reporting_replica | failover_replica | export | log | doc | image | activity | audit
    resource_id: str       # normalized resource ID (account_NN, search_NN, etc.)
    category: str | None   # data category from deletion_rules.csv (or None until classified)
    fields: dict[str, Any] # normalized fields: user_id, emails, phones, email_hash, status, toggles, etc.
    present: bool = True   # True if snapshot shows record exists; False if explicit deletion tombstone/absent


@dataclass(frozen=True)
class UnparsedEvidenceRecord:
    """
    Explicit record for any evidence file or section that yielded no valid observations.
    Ensures zero silent failures across the 94 evidence files.
    """
    file_id: str
    file_path: str
    reason: str
    error: str | None = None


@dataclass(frozen=True)
class Case:
    """
    A single deletion audit request from deletion_requests.csv.
    """
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str   # COMPLETE | PARTIALLY_COMPLETE | NOT_STARTED (claim)
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True)
class Identity:
    """
    Reconstructed identity of the data subject.
    """
    user_id: str
    current_email: str
    all_emails: frozenset[str]
    all_phones: frozenset[str]
    all_hashes: frozenset[str]
    name: str | None
    is_ambiguous: bool = False
    evidence_audit_ids: tuple[str, ...] = ()  # citable audit_id entries used in resolution


@dataclass(frozen=True)
class Step:
    """
    One step in steps_json for output.csv.
    """
    step_no: int
    phase: str        # FINDING | REMEDIATION | VERIFICATION
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str  # citable file_id / activity_id / audit_id, or "" for future steps

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }
