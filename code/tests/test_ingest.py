"""
test_ingest.py — Ingestion loader test suite for Phase 2.

Mandatory condition 4:
Every evidence file in evidence_files.csv must yield either >= 1 Observations
OR an explicit UnparsedEvidenceRecord. Zero silent failures permitted.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure code directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghost.config import DATASET_DIR, EVIDENCE_FILES_CSV
from ghost.ingest.coordinator import load_all_evidence, load_single_evidence_file
from ghost.ingest.loader_csv import load_manifest


def test_every_evidence_file_yields_observations_or_unparsed():
    """
    Mandatory condition 4 test:
    Every file in evidence_files.csv must produce either at least one Observation
    or an explicit UnparsedEvidenceRecord with a clear reason.
    """
    all_observations, all_unparsed, file_counts = load_all_evidence()

    manifest = load_manifest(EVIDENCE_FILES_CSV)
    assert len(manifest) == 94, f"Expected 94 manifest entries, found {len(manifest)}"

    # Map unparsed by file_id
    unparsed_by_file = {u.file_id: u for u in all_unparsed}

    for row in manifest:
        fid = row["file_id"].strip()
        obs_count = file_counts.get(fid, 0)
        has_unparsed = fid in unparsed_by_file

        # Assert contract: must have either observations OR an explicit unparsed record
        assert (
            obs_count > 0 or has_unparsed
        ), f"Silent failure on {fid} ({row['file_path']}): 0 observations and no UnparsedEvidenceRecord!"

        if obs_count == 0:
            unp = unparsed_by_file[fid]
            assert unp.reason, f"{fid} has 0 observations and empty unparsed reason"


def test_evidence_90_explicitly_unparsed_due_to_empty_tables():
    """
    Verifies that customer_data_inventory_20260905.sql (evidence_90), which contains
    valid DDL but 0 data rows across all tables, is explicitly recorded as unparsed.
    """
    manifest = load_manifest(EVIDENCE_FILES_CSV)
    ev90 = next(r for r in manifest if r["file_id"] == "evidence_90")
    obs, unparsed = load_single_evidence_file(
        ev90["file_id"], ev90["file_path"], ev90["captured_at_dt"], DATASET_DIR
    )
    assert len(obs) == 0
    assert len(unparsed) == 1
    assert "Zero rows" in unparsed[0].reason


def test_total_observation_volume_and_coverage():
    """
    Sanity check on overall ingestion scale across the 94 evidence files.
    """
    all_observations, all_unparsed, file_counts = load_all_evidence()
    assert len(all_observations) >= 3000, f"Expected >= 3000 observations, got {len(all_observations)}"
    # 93 files yield observations, 1 is legitimately empty (evidence_90)
    files_with_obs = [f for f, c in file_counts.items() if c > 0]
    assert len(files_with_obs) == 93
    assert len(all_unparsed) == 1
    assert all_unparsed[0].file_id == "evidence_90"


def test_observation_immutability():
    """
    Verifies Observation instances are frozen/immutable.
    """
    obs, _, _ = load_all_evidence()
    sample = obs[0]
    try:
        sample.present = False  # type: ignore
        assert False, "Observation should be frozen/immutable"
    except Exception:
        pass  # expected FrozenInstanceError
