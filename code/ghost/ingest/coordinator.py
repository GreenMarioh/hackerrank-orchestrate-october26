"""
coordinator.py — Unified ingestion coordinator for all 94 evidence files.

Loads every file listed in evidence_files.csv, ensures zero silent failures,
collects SnapshotCoverage records for state verification in Phase 6,
and records explicit UnparsedEvidenceRecord entries if genuine read failures occur.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ghost.config import DATASET_DIR, EVIDENCE_FILES_CSV
from ghost.ingest.loader_csv import load_manifest
from ghost.ingest.loader_image import load_image_evidence
from ghost.ingest.loader_json import load_json_evidence
from ghost.ingest.loader_logs import load_log_evidence
from ghost.ingest.loader_pdf import load_pdf_evidence
from ghost.ingest.loader_sql import load_sql_evidence
from ghost.ingest.loader_txt import load_txt_evidence
from ghost.models import Observation, SnapshotCoverage, UnparsedEvidenceRecord


def load_single_evidence_file(
    file_id: str,
    relative_path: str,
    captured_at: datetime,
    base_dir: Path = DATASET_DIR,
) -> tuple[list[Observation], list[SnapshotCoverage], list[UnparsedEvidenceRecord]]:
    """
    Dispatches a single evidence file to its appropriate format loader.
    """
    full_path = base_dir / relative_path
    ext = full_path.suffix.lower()

    if not full_path.exists():
        return [], [], [UnparsedEvidenceRecord(file_id, str(full_path), "File does not exist on disk")]

    if ext == ".sql":
        return load_sql_evidence(full_path, file_id, captured_at)
    elif ext == ".json":
        return load_json_evidence(full_path, file_id, captured_at)
    elif ext == ".log":
        obs, unp = load_log_evidence(full_path, file_id, captured_at)
        return obs, [], unp
    elif ext == ".pdf":
        obs, unp = load_pdf_evidence(full_path, file_id, captured_at)
        return obs, [], unp
    elif ext == ".png":
        obs, unp = load_image_evidence(full_path, file_id, captured_at)
        return obs, [], unp
    elif ext == ".txt":
        obs, unp = load_txt_evidence(full_path, file_id, captured_at)
        return obs, [], unp
    else:
        return [], [], [UnparsedEvidenceRecord(file_id, str(full_path), f"Unsupported file extension: {ext}")]


def load_all_evidence(
    manifest_path: Path = EVIDENCE_FILES_CSV,
    base_dir: Path = DATASET_DIR,
) -> tuple[list[Observation], list[SnapshotCoverage], list[UnparsedEvidenceRecord], dict[str, int]]:
    """
    Loads all evidence files listed in the manifest.
    Returns:
      (all_observations, all_coverages, all_unparsed_records, file_coverage_counts)
    """
    manifest_rows = load_manifest(manifest_path)
    all_observations: list[Observation] = []
    all_coverages: list[SnapshotCoverage] = []
    all_unparsed: list[UnparsedEvidenceRecord] = []
    file_counts: dict[str, int] = {}

    for row in manifest_rows:
        file_id = row["file_id"].strip()
        rel_path = row["file_path"].strip()
        captured_at = row["captured_at_dt"]

        obs, cov, unparsed = load_single_evidence_file(file_id, rel_path, captured_at, base_dir)
        all_observations.extend(obs)
        all_coverages.extend(cov)
        all_unparsed.extend(unparsed)
        file_counts[file_id] = len(obs)

    return all_observations, all_coverages, all_unparsed, file_counts
