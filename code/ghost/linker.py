"""
linker.py — Anchor-and-Expand Evidence Linker for Phase 5.

Links evidence observations, system activities, and resources to the deletion subject:
1. Subject Anchor: Find direct alias matches across evidence observations and activity events
   (emails, phones, hashes, name, user_id).
2. Catalog Linkage: Ground catalog events (LINK_RESOURCE_IDENTITY) occurring <= case.audit_at.
3. Activity Clustering / Expansion: Cluster activity events of other types around anchors'
   event timestamps (e.g. ±30-60 min) or reported_at window, corroborating candidates.
4. Confidence Assignment:
   - HIGH: Direct alias match in evidence content or LINK_RESOURCE_IDENTITY catalog event.
   - MEDIUM: Resource linked via activity event citing alias or tight timestamp cluster.
   - LOW: Wide window activity candidates without direct alias grounding.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.config import SYSTEM_ACTIVITY_CSV
from ghost.identity import _parse_iso
from ghost.models import Identity, Observation
from ghost.rules import RuleEngine, default_rule_engine


@dataclass(frozen=True)
class LinkedResource:
    resource_id: str
    system_id: str
    category: str | None
    confidence: str                 # HIGH | MEDIUM | LOW
    evidence_ids: tuple[str, ...]   # file_ids or activity_ids proving linkage
    first_seen: datetime
    is_anchor: bool
    rationale: str


class EvidenceLinker:
    """
    Anchor-and-expand evidence linker connecting resources to subjects.
    """

    def __init__(
        self,
        observations: list[Observation],
        activity_path: Path = SYSTEM_ACTIVITY_CSV,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.observations = observations
        self.rule_engine = rule_engine or default_rule_engine
        self.activities: list[dict[str, Any]] = []
        self._load_activities(activity_path)

    def _load_activities(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                dt = _parse_iso(r["event_time"])
                self.activities.append({
                    "activity_id": r["activity_id"].strip(),
                    "event_time": dt,
                    "event_type": r["event_type"].strip(),
                    "source_system": r["source_system"].strip(),
                    "target_system": r["target_system"].strip(),
                    "resource_id": r["resource_id"].strip(),
                    "reported_result": r["reported_result"].strip(),
                    "details": r["details"].strip(),
                    "details_lower": r["details"].strip().lower(),
                })

    def link_subject_resources(
        self,
        subject: Identity,
        audit_at: datetime,
        reported_at: datetime | None = None,
    ) -> dict[str, LinkedResource]:
        """
        Executes anchor-and-expand linking for a subject up to audit_at.
        Returns a mapping of resource_id -> LinkedResource.
        """
        linked: dict[str, LinkedResource] = {}
        anchor_times: list[datetime] = []

        # Build alias set and compiled word-boundary patterns for subject
        aliases: set[str] = {subject.user_id.lower()}
        for e in subject.all_emails:
            aliases.add(e.lower())
        for p in subject.all_phones:
            aliases.add(p.lower())
        for h in subject.all_hashes:
            aliases.add(h.lower())
        if subject.name and len(subject.name) >= 3:
            aliases.add(subject.name.lower())

        alias_patterns: list[tuple[str, re.Pattern]] = []
        for a in aliases:
            if len(a) >= 3:
                left_b = r"\b" if re.match(r"^\w", a) else r"(?<!\w)"
                right_b = r"\b" if re.search(r"\w$", a) else r"(?!\w)"
                alias_patterns.append((a, re.compile(left_b + re.escape(a) + right_b)))

        # -------------------------------------------------------------
        # 1. ANCHOR PHASE: Evidence observations matching aliases <= audit_at
        # -------------------------------------------------------------
        for obs in self.observations:
            effective_time = obs.file_captured_at or obs.captured_at
            if effective_time > audit_at:
                continue

            # Check if any field contains an alias (word-boundary safe)
            fields_str = json.dumps(obs.fields).lower()
            matched_alias = None
            for a, pattern in alias_patterns:
                if pattern.search(fields_str):
                    matched_alias = a
                    break

            if matched_alias:
                rid = obs.resource_id
                cat, _ = self.rule_engine.categorize_resource(
                    rid, system_id=obs.system_id, fields=obs.fields, explicit_category=obs.category
                )
                prev = linked.get(rid)
                ev_ids = tuple(sorted(set((prev.evidence_ids if prev else ()) + (obs.file_id,))))
                first_seen = min(prev.first_seen if prev else obs.captured_at, obs.captured_at)
                
                linked[rid] = LinkedResource(
                    resource_id=rid,
                    system_id=obs.system_id,
                    category=cat,
                    confidence="HIGH",
                    evidence_ids=ev_ids,
                    first_seen=first_seen,
                    is_anchor=True,
                    rationale=f"Evidence {obs.file_id} contains subject alias '{matched_alias}'",
                )
                anchor_times.append(obs.captured_at)

        # -------------------------------------------------------------
        # 2. CATALOG & ACTIVITY ANCHORS: Activity matching aliases <= audit_at
        # -------------------------------------------------------------
        for act in self.activities:
            if act["event_time"] > audit_at:
                continue

            matched_alias = None
            for a, pattern in alias_patterns:
                if pattern.search(act["details_lower"]):
                    matched_alias = a
                    break

            if matched_alias:
                rid = act["resource_id"]
                is_catalog = (act["event_type"] == "LINK_RESOURCE_IDENTITY")
                conf = "HIGH" if is_catalog else "HIGH"
                cat, _ = self.rule_engine.categorize_resource(rid, system_id=act["target_system"])
                
                prev = linked.get(rid)
                ev_ids = tuple(sorted(set((prev.evidence_ids if prev else ()) + (act["activity_id"],))))
                first_seen = min(prev.first_seen if prev else act["event_time"], act["event_time"])

                linked[rid] = LinkedResource(
                    resource_id=rid,
                    system_id=act["target_system"],
                    category=cat,
                    confidence=conf,
                    evidence_ids=ev_ids,
                    first_seen=first_seen,
                    is_anchor=True,
                    rationale=f"Activity {act['activity_id']} ({act['event_type']}) cites subject alias '{matched_alias}'",
                )
                anchor_times.append(act["event_time"])

        # -------------------------------------------------------------
        # 3. EXPAND PHASE: Corroborate activities clustered around anchor times
        # -------------------------------------------------------------
        # If no anchor times found, use reported_at if available
        reference_times = list(anchor_times)
        if reported_at and reported_at <= audit_at:
            reference_times.append(reported_at)

        if reference_times:
            for act in self.activities:
                if act["event_time"] > audit_at:
                    continue
                rid = act["resource_id"]
                if rid in linked:
                    continue  # Already linked with higher confidence

                t = act["event_time"]
                # Check proximity to any anchor time (e.g. within 30 minutes = 1800s)
                min_diff = min(abs((t - at).total_seconds()) for at in reference_times)
                if min_diff <= 1800:
                    cat, _ = self.rule_engine.categorize_resource(rid, system_id=act["target_system"])
                    linked[rid] = LinkedResource(
                        resource_id=rid,
                        system_id=act["target_system"],
                        category=cat,
                        confidence="MEDIUM",
                        evidence_ids=(act["activity_id"],),
                        first_seen=t,
                        is_anchor=False,
                        rationale=f"Activity {act['activity_id']} clustered within {int(min_diff)}s of subject anchor",
                    )
                elif min_diff <= 7200:
                    # Wide window (low confidence)
                    cat, _ = self.rule_engine.categorize_resource(rid, system_id=act["target_system"])
                    linked[rid] = LinkedResource(
                        resource_id=rid,
                        system_id=act["target_system"],
                        category=cat,
                        confidence="LOW",
                        evidence_ids=(act["activity_id"],),
                        first_seen=t,
                        is_anchor=False,
                        rationale=f"Activity {act['activity_id']} within wide window ({int(min_diff)}s) of anchor/reported_at",
                    )

        return linked
