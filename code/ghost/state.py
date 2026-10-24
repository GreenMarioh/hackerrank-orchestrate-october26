"""
state.py — Resource State Determination at audit_at for Phase 6.

Computes the ground-truth state of each linked resource at case.audit_at:
States:
- PRESENT_IDENTIFIED: Record exists and displays direct identifiers (email, phone, name, hash) or attributable user_id.
- PRESENT_REDACTED: Record exists with stable user_id only (no direct identifiers).
- PRESENT_ANONYMIZED: Record exists with no link to user at all.
- ABSENT: Proven absent by evidence (e.g. 404 lookup, explicit NOT_FOUND lookup, or absent from snapshot coverage).
- UNKNOWN: No snapshot covers this store at or before audit_at.

H7 Multi-Store Invariant:
Any store (primary or replica) still holding identified data counts as a remaining copy (PRESENT_IDENTIFIED).
Replication drift across primary vs regional vs failover replicas is evaluated: the most violating state wins.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ghost.linker import LinkedResource
from ghost.models import Identity, Observation, SnapshotCoverage
from ghost.rules import RuleEngine, default_rule_engine


@dataclass(frozen=True)
class StoreState:
    store: str
    state: str                 # PRESENT_IDENTIFIED | PRESENT_REDACTED | PRESENT_ANONYMIZED | ABSENT | UNKNOWN
    file_id: str               # file_id proving this state
    captured_at: datetime
    details: dict[str, Any]


@dataclass(frozen=True)
class ResourceState:
    resource_id: str
    system_id: str
    category: str | None
    overall_state: str         # PRESENT_IDENTIFIED | PRESENT_REDACTED | PRESENT_ANONYMIZED | ABSENT | UNKNOWN
    is_compliant: bool
    evidence_id: str           # Citable file_id proving compliance/violation (or latest snapshot)
    store_states: tuple[StoreState, ...]
    rationale: str


class StateEvaluator:
    """
    Evaluates resource state at audit_at across all stores and snapshot coverages.
    """

    def __init__(
        self,
        observations: list[Observation],
        coverages: list[SnapshotCoverage],
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.observations = observations
        self.coverages = coverages
        self.rule_engine = rule_engine or default_rule_engine

        # Index observations by resource_id
        self.obs_by_rid: dict[str, list[Observation]] = {}
        for o in self.observations:
            self.obs_by_rid.setdefault(o.resource_id, []).append(o)

        # Index coverages by system_id
        self.cov_by_sys: dict[str, list[SnapshotCoverage]] = {}
        for c in self.coverages:
            self.cov_by_sys.setdefault(c.system_id, []).append(c)

    def determine_resource_state(
        self,
        linked_res: LinkedResource,
        subject: Identity,
        audit_at: datetime,
    ) -> ResourceState:
        rid = linked_res.resource_id
        sys_id = linked_res.system_id
        cat = linked_res.category

        # Collect observations for this resource captured <= audit_at
        cand_obs = [
            o for o in self.obs_by_rid.get(rid, [])
            if o.captured_at <= audit_at
        ]

        store_states: list[StoreState] = []
        obs_by_store: dict[str, list[Observation]] = {}
        for o in cand_obs:
            obs_by_store.setdefault(o.store, []).append(o)

        # Build direct alias set for direct identifier checks (excluding stable user_id)
        direct_aliases: set[str] = set()
        for e in subject.all_emails:
            direct_aliases.add(e.lower())
        for p in subject.all_phones:
            direct_aliases.add(p.lower())
        for h in subject.all_hashes:
            direct_aliases.add(h.lower())
        if subject.name and len(subject.name) >= 3:
            direct_aliases.add(subject.name.lower())

        # Evaluate each store's latest observation
        for store, store_obs_list in obs_by_store.items():
            store_obs_list.sort(key=lambda x: x.captured_at)
            latest_obs = store_obs_list[-1]

            if not latest_obs.present:
                store_states.append(
                    StoreState(
                        store=store,
                        state="ABSENT",
                        file_id=latest_obs.file_id,
                        captured_at=latest_obs.captured_at,
                        details={"present": False, "status": "NOT_FOUND"},
                    )
                )
                continue

            f = latest_obs.fields
            def _valid_val(val: Any) -> bool:
                if val is None:
                    return False
                s = str(val).strip().lower()
                return s not in ("", "null", "none", "[redacted]")

            direct_keys = (
                "email", "phone", "name", "full_name", "display_name", "email_hash",
                "requester_email", "owner_email", "customer_email", "primary_email", "raw_identifier"
            )
            has_direct_id = any(
                _valid_val(f.get(k)) for k in direct_keys
            )
            if not has_direct_id:
                for k, v in f.items():
                    if v is None:
                        continue
                    v_str = str(v).lower()
                    if any(alias in v_str for alias in direct_aliases if len(alias) >= 4):
                        has_direct_id = True
                        break

            has_uid = any(
                _valid_val(f.get(k))
                for k in ("user_id", "customer_reference", "subject_reference")
            )

            # Check if fields display direct identifiers
            if has_direct_id:
                s_state = "PRESENT_IDENTIFIED"
            elif has_uid:
                s_state = "PRESENT_REDACTED"
            else:
                s_state = "PRESENT_ANONYMIZED"

            store_states.append(
                StoreState(
                    store=store,
                    state=s_state,
                    file_id=latest_obs.file_id,
                    captured_at=latest_obs.captured_at,
                    details=f,
                )
            )

        # Check SnapshotCoverage if no observations or all observations are ABSENT
        # To prove ABSENT, find latest snapshot covering this system_id <= audit_at
        latest_cov_file = ""
        cov_cand = [
            c for c in self.cov_by_sys.get(sys_id, [])
            if c.captured_at <= audit_at
        ]
        if cov_cand:
            cov_cand.sort(key=lambda x: x.captured_at, reverse=True)
            # Find the latest snapshot coverage
            latest_time = cov_cand[0].captured_at
            latest_scopes = [c for c in cov_cand if c.captured_at == latest_time]
            # Verify if rid is in any scope of latest coverage
            rid_in_latest = any(rid in c.resource_ids for c in latest_scopes)
            if not rid_in_latest:
                latest_cov_file = latest_scopes[0].file_id

        # H7: Multi-store aggregation
        # Priority: PRESENT_IDENTIFIED > PRESENT_REDACTED > PRESENT_ANONYMIZED > ABSENT > UNKNOWN
        identified_stores = [s for s in store_states if s.state == "PRESENT_IDENTIFIED"]
        redacted_stores = [s for s in store_states if s.state == "PRESENT_REDACTED"]
        anon_stores = [s for s in store_states if s.state == "PRESENT_ANONYMIZED"]
        absent_stores = [s for s in store_states if s.state == "ABSENT"]

        if identified_stores:
            overall = "PRESENT_IDENTIFIED"
            # Sort by captured_at to cite the latest remaining copy
            identified_stores.sort(key=lambda s: s.captured_at, reverse=True)
            violating_store = identified_stores[0]
            evidence_id = violating_store.file_id
            rationale = f"Resource holds identified PII in {violating_store.store} store ({violating_store.file_id})"
        elif redacted_stores:
            overall = "PRESENT_REDACTED"
            redacted_stores.sort(key=lambda s: s.captured_at, reverse=True)
            redacted_store = redacted_stores[0]
            evidence_id = redacted_store.file_id
            rationale = f"Resource is redacted with stable user_id in {redacted_store.store} store ({redacted_store.file_id})"
        elif anon_stores:
            overall = "PRESENT_ANONYMIZED"
            anon_stores.sort(key=lambda s: s.captured_at, reverse=True)
            anon_store = anon_stores[0]
            evidence_id = anon_store.file_id
            rationale = f"Resource is anonymized in {anon_store.store} store ({anon_store.file_id})"
        elif absent_stores:
            overall = "ABSENT"
            absent_stores.sort(key=lambda s: s.captured_at, reverse=True)
            abs_store = absent_stores[0]
            evidence_id = abs_store.file_id
            rationale = f"Resource is proven ABSENT by explicit lookup in {abs_store.file_id}"
        elif latest_cov_file:
            overall = "ABSENT"
            evidence_id = latest_cov_file
            rationale = f"Resource is absent from latest snapshot coverage {latest_cov_file} at {audit_at.isoformat()}"
        else:
            overall = "UNKNOWN"
            evidence_id = ""
            rationale = f"No evidence observation or snapshot coverage found for {sys_id} at or before audit_at"

        # Determine compliance against policy rule
        rule = self.rule_engine.rules_by_category.get(cat)
        required_action = rule.required_action if rule else "DELETE"

        # Check special categories: BACKUP_ARCHIVE and DATA_FLOW
        if cat == "BACKUP_ARCHIVE":
            restore_open = any(
                s.details.get("restore_allowed") in (True, 1, "1", "true", "True")
                or s.details.get("deletion_block") in (False, 0, "0", "false", "False")
                or s.details.get("eligible") in (True, 1, "1", "true", "True")
                for s in store_states
            )
            is_compliant = not restore_open
            if restore_open:
                overall = "ACTIVE"
                active_stores = [
                    s for s in store_states
                    if (s.details.get("restore_allowed") in (True, 1, "1", "true", "True")
                        or s.details.get("deletion_block") in (False, 0, "0", "false", "False")
                        or s.details.get("eligible") in (True, 1, "1", "true", "True"))
                ]
                active_stores.sort(key=lambda s: s.captured_at, reverse=True)
                evidence_id = active_stores[0].file_id if active_stores else (store_states[0].file_id if store_states else "")
                rationale = f"Backup archive has active restore risk in {evidence_id}"
            else:
                overall = "BLOCKED"
                store_states.sort(key=lambda s: s.captured_at, reverse=True)
                evidence_id = store_states[0].file_id if store_states else ""
                rationale = f"Backup archive restore is blocked in {evidence_id}"
        elif cat == "DATA_FLOW":
            flow_open = any(
                s.details.get("enabled") in (True, 1, "1", "true", "True")
                for s in store_states
            )
            is_compliant = not flow_open
            if flow_open:
                overall = "ACTIVE"
                active_stores = [
                    s for s in store_states
                    if s.details.get("enabled") in (True, 1, "1", "true", "True")
                ]
                active_stores.sort(key=lambda s: s.captured_at, reverse=True)
                evidence_id = active_stores[0].file_id if active_stores else (store_states[0].file_id if store_states else "")
                rationale = f"Data flow sync is active (enabled=True) in {evidence_id}"
            else:
                overall = "DISABLED"
                store_states.sort(key=lambda s: s.captured_at, reverse=True)
                evidence_id = store_states[0].file_id if store_states else ""
                rationale = f"Data flow sync is disabled in {evidence_id}"
        elif cat == "ACCOUNT_TOMBSTONE":
            # Tombstone is compliant only if direct identifiers are absent (PRESENT_REDACTED)
            is_compliant = (overall == "PRESENT_REDACTED")
        elif required_action == "DELETE":
            is_compliant = (overall == "ABSENT")
        elif required_action == "REDACT":
            is_compliant = (overall in ("PRESENT_REDACTED", "ABSENT"))
        elif required_action == "ANONYMIZE":
            is_compliant = (overall in ("PRESENT_ANONYMIZED", "ABSENT"))
        elif required_action == "RETAIN":
            is_compliant = (overall in ("PRESENT_IDENTIFIED", "PRESENT_REDACTED", "PRESENT_ANONYMIZED"))
        else:
            is_compliant = (overall == "ABSENT")

        return ResourceState(
            resource_id=rid,
            system_id=sys_id,
            category=cat,
            overall_state=overall,
            is_compliant=is_compliant,
            evidence_id=evidence_id,
            store_states=tuple(store_states),
            rationale=rationale,
        )
