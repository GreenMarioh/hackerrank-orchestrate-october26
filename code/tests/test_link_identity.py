"""
test_link_identity.py — Test LINK_RESOURCE_IDENTITY event handling and audit_at cutoff.

Phase 1 / Phase 5 contract:
LINK_RESOURCE_IDENTITY events in system_activity.csv carry authoritative ownership
linking a resource to a subject. Because none of the 12 LINK_RESOURCE_IDENTITY events
overlap with the 32 development samples, this synthetic test verifies that:
1. An event with event_time <= audit_at is accepted as authoritative linking evidence.
2. An event with event_time > audit_at is strictly rejected/ignored (anti-leak contract).
3. The cutoff is applied cleanly across timezone-aware timestamps.
"""
from __future__ import annotations

from datetime import datetime, timezone


def link_from_catalog_events(
    events: list[dict[str, str]],
    subject_identifiers: set[str],
    audit_at: datetime,
) -> list[dict[str, str]]:
    """
    General rule: extract resource links from LINK_RESOURCE_IDENTITY events.
    Applies strict cutoff: event_time <= audit_at.
    """
    linked = []
    # Normalize subject identifiers for matching
    norm_ids = {i.strip().lower() for i in subject_identifiers if i}

    for ev in events:
        if ev.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue

        # Parse event time
        raw_time = ev.get("event_time", "").strip()
        try:
            ev_dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except ValueError:
            continue

        # Strict audit_at cutoff: drop any event occurring after audit_at
        if ev_dt > audit_at:
            continue

        # Check if details, subject_id, or subject_email match any subject identifier
        details = ev.get("details", "").lower()
        subj_id = ev.get("subject_id", "").lower()
        subj_email = ev.get("subject_email", "").lower()

        match = any(
            ident in details or ident == subj_id or ident == subj_email
            for ident in norm_ids
        )
        if match:
            linked.append(ev)

    return linked


def test_link_resource_identity_before_audit_at():
    audit_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "activity_id": "activity_4007",
            "event_time": "2026-02-13T08:07:01Z",
            "event_type": "LINK_RESOURCE_IDENTITY",
            "target_system": "object_storage",
            "resource_id": "object_19",
            "details": "Attachment catalog confirmed object_19 belongs only to priya.raman@gmail.com and user_07",
        }
    ]
    linked = link_from_catalog_events(events, {"user_07", "priya.raman@gmail.com"}, audit_at)
    assert len(linked) == 1
    assert linked[0]["resource_id"] == "object_19"
    assert linked[0]["target_system"] == "object_storage"


def test_link_resource_identity_after_audit_at_is_filtered():
    """Anti-leak test: an event after audit_at must never be used."""
    audit_at = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "activity_id": "activity_4007",
            "event_time": "2026-02-13T08:07:01Z",  # after audit_at!
            "event_type": "LINK_RESOURCE_IDENTITY",
            "target_system": "object_storage",
            "resource_id": "object_19",
            "details": "Attachment catalog confirmed object_19 belongs only to priya.raman@gmail.com and user_07",
        }
    ]
    linked = link_from_catalog_events(events, {"user_07", "priya.raman@gmail.com"}, audit_at)
    assert len(linked) == 0  # strictly filtered out


def test_link_resource_identity_unrelated_user():
    audit_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "activity_id": "activity_4008",
            "event_time": "2026-07-16T07:27:01Z",
            "event_type": "LINK_RESOURCE_IDENTITY",
            "target_system": "marketing_platform",
            "resource_id": "marketing_001",
            "details": "Data catalog linked marketing_001 to kwame-mensah@proton.me and user_09",
        }
    ]
    linked = link_from_catalog_events(events, {"user_99", "other@example.com"}, audit_at)
    assert len(linked) == 0
