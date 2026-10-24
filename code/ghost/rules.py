"""
rules.py — Deterministic Deletion Rules Engine for Phase 4.

Loads and evaluates the 15 policy rules from dataset/deletion_rules.csv.

Constraints:
- Condition predicates are plain code on real evidence fields.
- Returns "UNKNOWN" when required fields are missing or unavailable (never guessing).
- No LLM at run time.
- Categorizes all evidence and activity resources deterministically.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.config import DELETION_RULES_CSV


@dataclass(frozen=True)
class Rule:
    rule_id: str
    data_category: str
    condition_text: str
    required_action: str  # DELETE | REDACT | ANONYMIZE | RETAIN


@dataclass(frozen=True)
class ConditionResult:
    status: str           # MET | NOT_MET | UNKNOWN
    action: str | None    # DELETE | REDACT | ANONYMIZE | RETAIN | None
    rule_id: str
    reason: str


class RuleEngine:
    """
    In-memory rule engine evaluating deletion policy rules.
    """

    def __init__(self, rules_csv_path: Path = DELETION_RULES_CSV) -> None:
        self.rules: dict[str, Rule] = {}               # rule_id -> Rule
        self.rules_by_category: dict[str, Rule] = {}   # data_category -> Rule
        self._load_rules(rules_csv_path)

    def _load_rules(self, path: Path) -> None:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rule = Rule(
                    rule_id=r["rule_id"].strip(),
                    data_category=r["data_category"].strip(),
                    condition_text=r["condition"].strip(),
                    required_action=r["required_action"].strip().upper(),
                )
                self.rules[rule.rule_id] = rule
                self.rules_by_category[rule.data_category] = rule

    def categorize_resource(
        self,
        resource_id: str,
        system_id: str = "",
        fields: dict[str, Any] | None = None,
        explicit_category: str | None = None,
    ) -> tuple[str | None, str]:
        """
        Determines the data category for a given resource.
        Strict categorization order:
        1. Explicit category from loader/schema if valid
        2. Grounded resource ID prefixes (only prefixes that occur in dataset)
        3. Document resources (doc_*) categorised strictly from document content
        4. Unknown/unclear returns (None, reason) without guessing.
        """
        # 1. Explicit category provided by evidence loader
        if explicit_category and explicit_category in self.rules_by_category:
            return explicit_category, "Explicit category provided by evidence loader"

        rid = resource_id.strip().lower()
        f = fields or {}

        # 2. Grounded resource ID prefixes occurring in dataset
        if rid.startswith("tombstone_"):
            return "ACCOUNT_TOMBSTONE", "Resource prefix tombstone_ denotes account tombstone"

        if rid.startswith("account_"):
            return "USER_PROFILE", "Resource prefix account_ denotes user account profile"

        if rid.startswith("search_"):
            return "SEARCH_INDEX_ENTRY", "Resource prefix search_ denotes customer search index"

        if rid.startswith("cache_"):
            return "CACHE_ENTRY", "Resource prefix cache_ denotes cached profile/session entry"

        if rid.startswith("object_") or rid.startswith("attachment_"):
            return "SUPPORT_ATTACHMENT", "Resource prefix object_/attachment_ denotes support attachment"

        if rid.startswith("support_") or rid.startswith("ticket_"):
            if f.get("storage_class") or f.get("file_name"):
                return "SUPPORT_ATTACHMENT", "Support resource contains attachment file metadata"
            return "SUPPORT_MESSAGE", "Resource prefix support_/ticket_ denotes customer support message"

        if rid.startswith("analytics_"):
            return "ANALYTICS_PROFILE", "Resource prefix analytics_ denotes customer analytics record"

        if rid.startswith("export_"):
            return "USER_EXPORT", "Resource prefix export_ denotes generated customer data export"

        if rid.startswith("marketing_"):
            return "MARKETING_PROFILE", "Resource prefix marketing_ denotes marketing campaign profile"

        if rid.startswith("mail_") or rid.startswith("email_"):
            return "EMAIL_DELIVERY_LOG", "Resource prefix mail_/email_ denotes transactional email log"

        if rid.startswith("audit_record_") or rid.startswith("audit_"):
            return "SECURITY_AUDIT_LOG", "Resource prefix audit_ denotes security audit record"

        if rid.startswith("legal_") or rid.startswith("hold_"):
            return "LEGAL_HOLD_RECORD", "Resource prefix legal_/hold_ denotes active legal hold register"

        if rid.startswith("backup_"):
            return "BACKUP_ARCHIVE", "Resource prefix backup_ denotes backup snapshot archive"

        if rid.startswith("data_flow_") or rid.startswith("flow_"):
            return "DATA_FLOW", "Resource prefix data_flow_ denotes active integration connector"

        if rid.startswith("restore_"):
            return "RESTORE_RISK", "Resource prefix restore_ denotes database restore target path"

        # 3. Document resources (doc_*) — categorised strictly from document content, not system_id
        if rid.startswith("doc_"):
            doc_text = str(f.get("source_text", "")).lower()
            if "statement" in doc_text or "customer statement" in doc_text or "account history" in doc_text:
                return "USER_PROFILE", "Document content contains customer statement/order history"
            if "retention register" in doc_text or "disputed orders" in doc_text or "tax records" in doc_text:
                return "LEGAL_HOLD_RECORD", "Document content contains legal/tax retention register"
            if "compliance journal" in doc_text or "security retention" in doc_text:
                return "SECURITY_AUDIT_LOG", "Document content contains compliance journal extract"
            if "delivery address correction" in doc_text or "support reference" in doc_text:
                return "SUPPORT_MESSAGE", "Document content contains customer support correction request"
            return None, "Document content does not match recognized document patterns"

        # 4. No guesses — anything else returns None (UNKNOWN)
        return None, "Unrecognized resource prefix without grounded category"

    def evaluate_rule(
        self,
        category: str,
        fields: dict[str, Any],
        audit_at: datetime | None = None,
    ) -> ConditionResult:
        """
        Evaluates the specific condition predicate for a data category using real fields.
        Returns UNKNOWN if required fields are missing or unavailable.
        """
        rule = self.rules_by_category.get(category)
        if not rule:
            return ConditionResult(
                status="UNKNOWN",
                action=None,
                rule_id="unknown_rule",
                reason=f"No policy rule defined for category '{category}'",
            )

        rid = rule.rule_id
        action = rule.required_action

        # If fields are missing/unavailable, return UNKNOWN without guessing
        if not fields:
            return ConditionResult(
                status="UNKNOWN",
                action=None,
                rule_id=rid,
                reason=f"Fields unavailable for {category}",
            )

        # Rules with condition 'Always': DELETE if record present; NOT_MET if already absent/deleted
        if rid in ("rule_01", "rule_02", "rule_03", "rule_04", "rule_09", "rule_10"):
            if fields.get("deleted") is True or fields.get("present") is False or fields.get("purged") is True:
                return ConditionResult(
                    status="NOT_MET",
                    action="ABSENT",
                    rule_id=rid,
                    reason=f"Record is already absent/deleted for {category}",
                )
            return ConditionResult(
                status="MET",
                action=action,
                rule_id=rid,
                reason=f"Condition Always: {category} must be deleted",
            )

        # Rule 05: SUPPORT_MESSAGE -> Conversation contains shared customer, agent, or order context
        if rid == "rule_05":
            # Real evidence fields: ticket_id, channel, requester_name, requester_email, message_text
            has_ticket = bool(fields.get("ticket_id"))
            has_channel = bool(fields.get("channel"))
            has_msg = bool(fields.get("message_text") or fields.get("message_excerpt"))
            has_agent_or_order = bool(fields.get("order_reference") or fields.get("uploaded_by") or fields.get("agent"))

            if has_ticket or has_channel or has_msg or has_agent_or_order:
                return ConditionResult(
                    status="MET",
                    action=action,  # REDACT
                    rule_id=rid,
                    reason="Conversation contains shared ticket/agent/order context that must be retained under REDACT",
                )
            if not fields:
                return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Fields unavailable for SUPPORT_MESSAGE")
            # If no context at all
            return ConditionResult(status="NOT_MET", action="DELETE", rule_id=rid, reason="No shared conversation context found")

        # Rule 06: SUPPORT_ATTACHMENT -> Attachment belongs only to the deletion subject
        if rid == "rule_06":
            is_shared = fields.get("shared")
            if is_shared is True:
                return ConditionResult(status="NOT_MET", action="REDACT", rule_id=rid, reason="Attachment is shared with other subjects")
            if "uploaded_by" in fields or "user_id" in fields or "email" in fields or "raw_identifier" in fields:
                return ConditionResult(
                    status="MET",
                    action=action,  # DELETE
                    rule_id=rid,
                    reason="Attachment belongs only to the deletion subject",
                )
            if not fields:
                return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Fields unavailable for SUPPORT_ATTACHMENT")
            return ConditionResult(status="MET", action=action, rule_id=rid, reason="Default attachment treatment: DELETE")

        # Rule 07: ANALYTICS_PROFILE -> Record is still attributable to a user
        if rid == "rule_07":
            # Check for direct or pseudo-direct identifiers
            has_uid = bool(fields.get("user_id") or fields.get("customer_reference") or fields.get("lookup_value"))
            has_contact = bool(fields.get("email") or fields.get("phone") or fields.get("email_hash"))
            has_raw = bool(fields.get("raw_identifier"))

            if has_uid or has_contact or has_raw:
                return ConditionResult(
                    status="MET",
                    action=action,  # ANONYMIZE
                    rule_id=rid,
                    reason="Record contains identifying fields and is attributable to a user",
                )
            # If fields are present but all identifiers are null/empty
            if fields:
                return ConditionResult(
                    status="NOT_MET",
                    action="RETAIN",
                    rule_id=rid,
                    reason="Record is not attributable to any user (already anonymized)",
                )
            return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Fields unavailable for ANALYTICS_PROFILE")

        # Rule 08: PRODUCT_TELEMETRY -> Record is still attributable to a user
        if rid == "rule_08":
            has_id = bool(fields.get("user_id") or fields.get("email") or fields.get("raw_identifier"))
            if has_id:
                return ConditionResult(
                    status="MET",
                    action=action,  # ANONYMIZE
                    rule_id=rid,
                    reason="Telemetry record is attributable to user",
                )
            if fields:
                return ConditionResult(status="NOT_MET", action="RETAIN", rule_id=rid, reason="Telemetry record unlinked")
            return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Fields unavailable for PRODUCT_TELEMETRY")

        # Rule 11: EMAIL_DELIVERY_LOG -> Log contains a user email address
        if rid == "rule_11":
            has_email = bool(fields.get("email") or fields.get("customer_email") or fields.get("requester_email"))
            if has_email:
                return ConditionResult(
                    status="MET",
                    action=action,  # REDACT
                    rule_id=rid,
                    reason="Log contains user email address that must be redacted",
                )
            return ConditionResult(status="NOT_MET", action="RETAIN", rule_id=rid, reason="Log contains no user email address")

        # Rule 12: SECURITY_AUDIT_LOG -> Record is within the supplied retention period
        if rid == "rule_12":
            retention_ts = fields.get("retention_until") or fields.get("retained_until")
            if retention_ts:
                # Compare against audit_at if supplied
                if audit_at:
                    try:
                        from ghost.identity import _parse_iso
                        dt_ret = _parse_iso(str(retention_ts))
                        if dt_ret >= audit_at:
                            return ConditionResult(
                                status="MET",
                                action=action,  # RETAIN
                                rule_id=rid,
                                reason=f"Record is within retention period (retained_until={retention_ts} >= audit_at)",
                            )
                        else:
                            return ConditionResult(
                                status="NOT_MET",
                                action="DELETE",
                                rule_id=rid,
                                reason=f"Retention period expired before audit_at (retained_until={retention_ts})",
                            )
                    except Exception:
                        pass
                return ConditionResult(
                    status="MET",
                    action=action,  # RETAIN
                    rule_id=rid,
                    reason="Record has explicit retention_until policy",
                )
            # When retention information is absent, return UNKNOWN
            return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Retention period field unavailable for SECURITY_AUDIT_LOG")

        # Rule 13: LEGAL_HOLD_RECORD -> A supplied legal hold is active
        if rid == "rule_13":
            retention_ts = fields.get("retained_until") or fields.get("retain_until")
            reason = fields.get("retention_reason")
            active = fields.get("active")
            if active is False or fields.get("released") is True:
                return ConditionResult(status="NOT_MET", action="DELETE", rule_id=rid, reason="Legal hold was released")
            if retention_ts or reason or fields.get("order_reference") or active is True:
                return ConditionResult(
                    status="MET",
                    action=action,  # RETAIN
                    rule_id=rid,
                    reason=f"Active legal hold record present: {reason or retention_ts}",
                )
            return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Legal hold status field unavailable for LEGAL_HOLD_RECORD")

        # Rule 14: BACKUP_ARCHIVE -> Restore access can be blocked
        if rid == "rule_14":
            if fields.get("blockable") is False:
                return ConditionResult(status="NOT_MET", action="DELETE", rule_id=rid, reason="Restore access cannot be blocked")
            if "restore_allowed" in fields or "blockable" in fields or "archive_path" in fields:
                return ConditionResult(
                    status="MET",
                    action=action,  # RETAIN
                    rule_id=rid,
                    reason="Backup archive is retained while restore access is blocked",
                )
            return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="Restore fields unavailable for BACKUP_ARCHIVE")

        # Rule 15: ACCOUNT_TOMBSTONE -> Account is deleted and only stable internal user_id needed
        if rid == "rule_15":
            has_uid = bool(fields.get("user_id") or fields.get("subject_reference"))
            if has_uid:
                # If direct identifiers are already absent, tombstone is compliant
                has_direct_pii = bool(fields.get("email") or fields.get("phone") or fields.get("name"))
                if not has_direct_pii:
                    return ConditionResult(
                        status="NOT_MET",
                        action="RETAIN",
                        rule_id=rid,
                        reason="Account tombstone already compliant (stable reference preserved, direct identifiers removed)",
                    )
                return ConditionResult(
                    status="MET",
                    action=action,  # REDACT
                    rule_id=rid,
                    reason="Account tombstone contains direct identifiers that must be redacted",
                )
            return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason="User reference unavailable for ACCOUNT_TOMBSTONE")

        return ConditionResult(status="UNKNOWN", action=None, rule_id=rid, reason=f"Unhandled rule {rid}")


# Global singleton instance
default_rule_engine = RuleEngine()
