"""
flows.py — Active Data Flow and Restore Risk Detection (Phase 7).

Implements:
1. Active continuous synchronization / data flow detection (REPORT_ACTIVE_DATA_FLOW, ACTIVE).
2. Active backup restore risk detection (REPORT_RESTORE_RISK, ACTIVE).
3. Evidence-grounded verification of disabled flows and blocked restores
   (VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED).
4. Defensible subject linkage requirement (prohibits temporal proximity guessing).
5. Strict temporal anti-leak enforcement (manifest captured_at <= audit_at).
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ghost.linker import LinkedResource
from ghost.models import Identity, Observation, Step


@dataclass(frozen=True)
class FlowRiskFinding:
    """
    Normalized result of an active data-flow or restore-risk audit.
    """
    resource_id: str
    system_id: str
    risk_type: str         # "ACTIVE_DATA_FLOW" | "RESTORE_RISK"
    state: str             # "ACTIVE" | "DISABLED" | "BLOCKED"
    is_risk: bool          # True if active hazard requiring remediation
    evidence_id: str       # Citable evidence proving current state (<= audit_at)
    details: str


class FlowRiskDetector:
    """
    Audits candidate flows and backup archives for active replication or restore hazards.
    """

    def __init__(
        self,
        observations: list[Observation],
        activity_path: Path | str | None = None,
    ) -> None:
        self.observations = observations
        self.activities: list[dict[str, Any]] = []
        if activity_path:
            p = Path(activity_path)
            if p.exists():
                with open(p, newline="", encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        self.activities.append(
                            {
                                "activity_id": row["activity_id"].strip(),
                                "event_time": datetime.fromisoformat(
                                    row["event_time"].replace("Z", "+00:00")
                                ),
                                "event_type": row["event_type"].strip(),
                                "source_system": row["source_system"].strip(),
                                "target_system": row["target_system"].strip(),
                                "resource_id": row["resource_id"].strip(),
                                "reported_result": row["reported_result"].strip(),
                                "details": row["details"].strip(),
                                "details_lower": row["details"].strip().lower(),
                            }
                        )

    def _has_defensible_subject_link(
        self,
        resource_id: str,
        subject: Identity,
        audit_at: datetime,
    ) -> bool:
        """
        Enforces Section 2A/2B: Temporal proximity alone is NOT sufficient.
        The resource must directly cite a subject alias in its evidence observations
        or explicit catalog/activity records <= audit_at.
        """
        # 1. Check subject aliases
        subject_aliases: set[str] = {subject.user_id.lower()}
        for e in subject.all_emails:
            subject_aliases.add(e.lower())
        for p in subject.all_phones:
            subject_aliases.add(p.lower())
        for h in subject.all_hashes:
            subject_aliases.add(h.lower())
        if subject.name and len(subject.name) >= 3:
            subject_aliases.add(subject.name.lower())

        alias_patterns: list[tuple[str, re.Pattern]] = []
        for a in subject_aliases:
            if len(a) >= 3:
                left_b = r"\b" if re.match(r"^\w", a) else r"(?<!\w)"
                right_b = r"\b" if re.search(r"\w$", a) else r"(?!\w)"
                alias_patterns.append((a, re.compile(left_b + re.escape(a) + right_b)))

        # Check evidence observations
        for o in self.observations:
            if o.resource_id == resource_id:
                if o.file_captured_at and o.file_captured_at > audit_at:
                    continue
                if o.captured_at > audit_at:
                    continue
                fields_str = json.dumps(o.fields).lower()
                for _, pat in alias_patterns:
                    if pat.search(fields_str):
                        return True

        # Check activity records
        for act in self.activities:
            if act["resource_id"] == resource_id:
                if act["event_time"] > audit_at:
                    continue
                for _, pat in alias_patterns:
                    if pat.search(act["details_lower"]):
                        return True

        return False

    def audit_resource(
        self,
        resource_id: str,
        system_id: str,
        subject: Identity,
        audit_at: datetime,
    ) -> FlowRiskFinding | None:
        """
        Evaluates the active/disabled/blocked state of a data flow or backup resource at audit_at.
        """
        is_flow = "data_flow" in resource_id or system_id == "integration_service"
        is_backup = "backup" in resource_id or system_id == "backup_service"

        if not (is_flow or is_backup):
            return None

        # Verify defensible subject ownership
        if not self._has_defensible_subject_link(resource_id, subject, audit_at):
            return None

        # Collect observations <= audit_at
        res_obs: list[Observation] = []
        for o in self.observations:
            if o.resource_id == resource_id:
                if o.file_captured_at and o.file_captured_at > audit_at:
                    continue
                if o.captured_at > audit_at:
                    continue
                res_obs.append(o)

        # Sort observations by captured_at descending to prioritize latest evidence
        res_obs.sort(key=lambda x: (x.file_captured_at or x.captured_at, x.captured_at), reverse=True)

        # Collect relevant activities <= audit_at
        res_acts = [
            a for a in self.activities
            if a["resource_id"] == resource_id and a["event_time"] <= audit_at
        ]
        res_acts.sort(key=lambda x: x["event_time"], reverse=True)

        if is_flow:
            return self._evaluate_flow(resource_id, system_id, res_obs, res_acts)
        else:
            return self._evaluate_backup(resource_id, system_id, res_obs, res_acts)

    def _evaluate_flow(
        self,
        resource_id: str,
        system_id: str,
        obs: list[Observation],
        acts: list[dict[str, Any]],
    ) -> FlowRiskFinding:
        """
        Determines whether a data flow is ACTIVE or DISABLED at audit_at.
        """
        # Default assumption is DISABLED unless evidence or activity proves ACTIVE
        is_active = False
        latest_citable = ""
        details = ""

        # Check latest evidence observations
        for o in obs:
            f = o.fields
            # Explicit enabled toggle
            en = f.get("enabled")
            st = str(f.get("status", "")).upper()
            lds = str(f.get("last_delivery_status", "")).lower()

            # Explicit disabled state takes precedence
            if (
                en is False
                or str(en).lower() in ("false", "0")
                or st in ("DISABLED", "STOPPED", "INACTIVE")
                or lds == "stopped"
            ):
                is_active = False
                latest_citable = o.file_id
                details = f"Disabled data flow observed in {o.file_id} (enabled={en}, status={st})"
                break
            # Active status strictly requires current enabled toggle or ACTIVE status
            elif (
                en is True
                or str(en).lower() in ("true", "1")
                or st == "ACTIVE"
                or (str(f.get("scheduler_registered", "")).lower() in ("true", "1") and en is not False)
            ):
                is_active = True
                latest_citable = o.file_id
                details = f"Active data flow observed in {o.file_id} (enabled={en}, status={st})"
                break

        # Check if newer activity event changes or establishes the state
        if acts:
            latest_act = acts[0]
            # If newer than the observation
            act_time = latest_act["event_time"]
            obs_time = obs[0].captured_at if obs else datetime.min.replace(tzinfo=act_time.tzinfo)
            if not obs or act_time >= obs_time:
                ev_type = latest_act["event_type"]
                res = latest_act["reported_result"]
                if ev_type == "DISABLE_DATA_FLOW" and res == "SUCCESS":
                    is_active = False
                    if not latest_citable:
                        latest_citable = latest_act["activity_id"]
                    details = f"Data flow disabled via {latest_act['activity_id']}"
                elif ev_type in ("CHECK_DATA_FLOW", "SYNC_RECORD") and res == "SUCCESS":
                    if "remains enabled" in latest_act["details_lower"] or "success" in latest_act["details_lower"]:
                        is_active = True
                        if not latest_citable:
                            latest_citable = latest_act["activity_id"]
                        details = f"Data flow verified active via {latest_act['activity_id']}"

        state = "ACTIVE" if is_active else "DISABLED"
        return FlowRiskFinding(
            resource_id=resource_id,
            system_id=system_id or "integration_service",
            risk_type="ACTIVE_DATA_FLOW",
            state=state,
            is_risk=is_active,
            evidence_id=latest_citable,
            details=details,
        )

    def _evaluate_backup(
        self,
        resource_id: str,
        system_id: str,
        obs: list[Observation],
        acts: list[dict[str, Any]],
    ) -> FlowRiskFinding:
        """
        Determines whether a backup archive poses an ACTIVE restore risk or is BLOCKED.
        """
        is_restore_risk = False
        latest_citable = ""
        details = ""

        # Check observations
        for o in obs:
            f = o.fields
            ra = f.get("restore_allowed")
            db = f.get("deletion_block")
            el = f.get("eligible")
            st = str(f.get("status", "")).upper()

            # Active restore risk: restore_allowed True, or eligible True and deletion_block False
            if (
                ra is True
                or str(ra).lower() in ("true", "1")
                or st == "ACTIVE"
                or (str(el).lower() in ("true", "1") and str(db).lower() in ("false", "0", "none", ""))
            ):
                is_restore_risk = True
                latest_citable = o.file_id
                details = f"Unblocked restore hazard in {o.file_id} (restore_allowed={ra}, deletion_block={db})"
                break
            elif (
                ra is False
                or str(ra).lower() in ("false", "0")
                or st in ("BLOCKED", "DISABLED")
                or str(db).lower() in ("true", "1")
            ):
                is_restore_risk = False
                latest_citable = o.file_id
                details = f"Blocked restore archive in {o.file_id} (restore_allowed={ra}, deletion_block={db})"
                break

        # Check if newer activity event establishes the state
        if acts:
            latest_act = acts[0]
            act_time = latest_act["event_time"]
            obs_time = obs[0].captured_at if obs else datetime.min.replace(tzinfo=act_time.tzinfo)
            if not obs or act_time >= obs_time:
                ev_type = latest_act["event_type"]
                res = latest_act["reported_result"]
                if ev_type == "BLOCK_RESTORE" and res == "SUCCESS":
                    is_restore_risk = False
                    if not latest_citable:
                        latest_citable = latest_act["activity_id"]
                    details = f"Restore blocked via {latest_act['activity_id']}"
                elif ev_type in ("CHECK_RESTORE_ACCESS", "RESTORE_BACKUP") and res == "SUCCESS":
                    if "can still be restored" in latest_act["details_lower"]:
                        is_restore_risk = True
                        if not latest_citable:
                            latest_citable = latest_act["activity_id"]
                        details = f"Restore risk confirmed via {latest_act['activity_id']}"

        state = "ACTIVE" if is_restore_risk else "BLOCKED"
        return FlowRiskFinding(
            resource_id=resource_id,
            system_id=system_id or "backup_service",
            risk_type="RESTORE_RISK",
            state=state,
            is_risk=is_restore_risk,
            evidence_id=latest_citable,
            details=details,
        )

    def detect_all_flows_and_risks(
        self,
        subject: Identity,
        linked_resources: dict[str, LinkedResource],
        audit_at: datetime,
    ) -> list[FlowRiskFinding]:
        """
        Audits all candidate flows and backup archives for the subject.
        """
        findings: list[FlowRiskFinding] = []
        for rid, lr in linked_resources.items():
            if "data_flow" in rid or "backup" in rid or lr.system_id in ("integration_service", "backup_service"):
                finding = self.audit_resource(rid, lr.system_id, subject, audit_at)
                if finding is not None:
                    findings.append(finding)
        return findings

    @staticmethod
    def generate_flow_steps(
        findings: list[FlowRiskFinding],
        is_complete: bool,
    ) -> tuple[list[Step], list[Step], list[Step]]:
        """
        Synthesizes finding, remediation, and verification steps for flows and restore risks.
        Returns:
            (finding_steps, remediation_steps, verification_steps)
        """
        finding_steps: list[Step] = []
        remediation_steps: list[Step] = []
        verification_steps: list[Step] = []

        # Sort findings deterministically: flows before backups, then by resource_id
        sorted_findings = sorted(
            findings,
            key=lambda x: (0 if x.risk_type == "ACTIVE_DATA_FLOW" else 1, x.resource_id),
        )

        for f in sorted_findings:
            if f.risk_type == "ACTIVE_DATA_FLOW":
                if f.is_risk:
                    # FINDING
                    finding_steps.append(
                        Step(
                            step_no=0,
                            phase="FINDING",
                            system_id=f.system_id,
                            resource_id=f.resource_id,
                            operation="REPORT_ACTIVE_DATA_FLOW",
                            state="ACTIVE",
                            evidence_id=f.evidence_id,
                        )
                    )
                    # REMEDIATION
                    remediation_steps.append(
                        Step(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=f.system_id,
                            resource_id=f.resource_id,
                            operation="DISABLE_DATA_FLOW",
                            state="DISABLED",
                            evidence_id="",
                        )
                    )
                    # POST-REMEDIATION VERIFICATION
                    verification_steps.append(
                        Step(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=f.system_id,
                            resource_id=f.resource_id,
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id="",
                        )
                    )
                else:
                    # COMPLETE case verification check
                    if is_complete:
                        verification_steps.append(
                            Step(
                                step_no=0,
                                phase="VERIFICATION",
                                system_id=f.system_id,
                                resource_id=f.resource_id,
                                operation="VERIFY_DATA_FLOW_DISABLED",
                                state="DISABLED",
                                evidence_id=f.evidence_id,
                            )
                        )

            elif f.risk_type == "RESTORE_RISK":
                if f.is_risk:
                    # FINDING
                    finding_steps.append(
                        Step(
                            step_no=0,
                            phase="FINDING",
                            system_id=f.system_id,
                            resource_id=f.resource_id,
                            operation="REPORT_RESTORE_RISK",
                            state="ACTIVE",
                            evidence_id=f.evidence_id,
                        )
                    )
                    # REMEDIATION
                    remediation_steps.append(
                        Step(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=f.system_id,
                            resource_id=f.resource_id,
                            operation="BLOCK_RESTORE",
                            state="BLOCKED",
                            evidence_id="",
                        )
                    )
                    # POST-REMEDIATION VERIFICATION
                    verification_steps.append(
                        Step(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=f.system_id,
                            resource_id=f.resource_id,
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id="",
                        )
                    )
                else:
                    # COMPLETE case verification check
                    if is_complete:
                        verification_steps.append(
                            Step(
                                step_no=0,
                                phase="VERIFICATION",
                                system_id=f.system_id,
                                resource_id=f.resource_id,
                                operation="VERIFY_RESTORE_BLOCKED",
                                state="BLOCKED",
                                evidence_id=f.evidence_id,
                            )
                        )

        return finding_steps, remediation_steps, verification_steps
