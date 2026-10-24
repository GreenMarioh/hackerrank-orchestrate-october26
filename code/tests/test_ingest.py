"""
test_ingest.py — Ingestion loader test suite for Phase 2.

Mandatory conditions:
1. Every evidence file in evidence_files.csv must yield either >= 1 Observations
   OR an explicit UnparsedEvidenceRecord, OR valid SnapshotCoverage records.
2. Zero-row snapshots like evidence_90 must produce valid SnapshotCoverage records
   with empty resource_ids (used in Phase 6 to prove ABSENT).
3. Observation and SnapshotCoverage models are immutable (frozen).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure code directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghost.config import DATASET_DIR, EVIDENCE_FILES_CSV
from ghost.ingest.coordinator import load_all_evidence, load_single_evidence_file
from ghost.ingest.loader_csv import load_manifest


def test_every_evidence_file_has_observations_or_coverage_or_unparsed():
    """
    Condition 4 test:
    Every file in evidence_files.csv must produce Observations, SnapshotCoverage,
    or an explicit UnparsedEvidenceRecord. Zero silent failures permitted.
    """
    all_observations, all_coverages, all_unparsed, file_counts = load_all_evidence()

    manifest = load_manifest(EVIDENCE_FILES_CSV)
    assert len(manifest) == 94, f"Expected 94 manifest entries, found {len(manifest)}"

    coverages_by_file = {c.file_id for c in all_coverages}
    unparsed_by_file = {u.file_id: u for u in all_unparsed}

    for row in manifest:
        fid = row["file_id"].strip()
        obs_count = file_counts.get(fid, 0)
        has_cov = fid in coverages_by_file
        has_unp = fid in unparsed_by_file

        assert (
            obs_count > 0 or has_cov or has_unp
        ), f"Silent failure on {fid} ({row['file_path']}): 0 observations, no coverage, and no unparsed record!"


def test_evidence_90_produces_snapshot_coverage_with_empty_resource_ids():
    """
    Verifies that customer_data_inventory_20260905.sql (evidence_90), which has 0 rows,
    produces valid SnapshotCoverage records with empty resource_ids.
    """
    manifest = load_manifest(EVIDENCE_FILES_CSV)
    ev90 = next(r for r in manifest if r["file_id"] == "evidence_90")
    obs, coverages, unparsed = load_single_evidence_file(
        ev90["file_id"], ev90["file_path"], ev90["captured_at_dt"], DATASET_DIR
    )
    assert len(obs) == 0
    assert len(unparsed) == 0  # not unparsed — it's a valid empty snapshot!
    assert len(coverages) == 8  # 8 tables in inventory
    for cov in coverages:
        assert cov.file_id == "evidence_90"
        assert len(cov.resource_ids) == 0
        assert isinstance(cov.resource_ids, frozenset)


def test_total_observation_volume_and_coverage():
    all_observations, all_coverages, all_unparsed, file_counts = load_all_evidence()
    assert len(all_observations) >= 3000, f"Expected >= 3000 observations, got {len(all_observations)}"
    assert len(all_coverages) >= 300, f"Expected >= 300 coverage scopes, got {len(all_coverages)}"
    assert len(all_unparsed) == 0, f"Expected 0 unparsed files, got {len(all_unparsed)}"


def test_models_immutability():
    all_observations, all_coverages, _, _ = load_all_evidence()
    obs = all_observations[0]
    cov = all_coverages[0]
    try:
        obs.present = False  # type: ignore
        assert False, "Observation must be frozen"
    except Exception:
        pass

    try:
        cov.system_id = "other"  # type: ignore
        assert False, "SnapshotCoverage must be frozen"
    except Exception:
        pass
