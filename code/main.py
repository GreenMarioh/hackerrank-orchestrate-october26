"""Ghost Data Still Exists — Production CLI Pipeline (Phase 8).

End-to-end deletion-audit engine reading evaluation cases from dataset/deletion_requests.csv
and producing the submission-contract root output.csv.

Usage:
    python code/main.py [--dataset-dir dataset] [--output output.csv] [--quiet]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# Add code directory to sys.path to enable absolute imports
REPO_ROOT = Path(__file__).resolve().parent.parent
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost.config import (
    DATASET_DIR as DEFAULT_DATASET_DIR,
    DELETION_REQUESTS_CSV as DEFAULT_DELETION_REQUESTS_CSV,
    DELETION_RULES_CSV as DEFAULT_RULES_CSV,
    EVIDENCE_FILES_CSV as DEFAULT_EVIDENCE_FILES_CSV,
    OUTPUT_PATH as DEFAULT_OUTPUT_CSV,
    SYSTEM_ACTIVITY_CSV as DEFAULT_SYSTEM_ACTIVITY_CSV,
    USER_AUDIT_LOG_CSV as DEFAULT_USER_AUDIT_LOG_CSV,
    USER_IDENTITIES_CSV as DEFAULT_USER_IDENTITIES_CSV,
)
from ghost.decision import AuditDecisionEngine, CaseAuditResult
from ghost.flows import FlowRiskDetector
from ghost.identity import IdentityResolver, _parse_iso
from ghost.ingest.coordinator import load_all_evidence
from ghost.intent import IntentClassifier
from ghost.linker import EvidenceLinker
from ghost.rules import RuleEngine, default_rule_engine
from ghost.state import StateEvaluator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ghost_audit")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Ghost Data Still Exists deletion audit pipeline."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help="Path to dataset directory containing participant CSV files and evidence.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "output.csv",
        help="Path to write the final prediction CSV (default: output.csv at repo root).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational progress logging.",
    )
    return parser.parse_args()


def build_pipeline(dataset_dir: Path) -> tuple[AuditDecisionEngine, list[dict[str, str]]]:
    """Pre-load evidence and build initialized AuditDecisionEngine."""
    logger.info("Initializing Ghost Audit Engine from dataset: %s", dataset_dir)
    t0 = time.time()

    activity_csv = dataset_dir / "system_activity.csv"
    identities_csv = dataset_dir / "user_identities.csv"
    audit_log_csv = dataset_dir / "user_audit_log.csv"
    rules_csv = dataset_dir / "deletion_rules.csv"
    requests_csv = dataset_dir / "deletion_requests.csv"

    # 1. Rule Engine
    rule_engine = RuleEngine(rules_csv) if rules_csv.exists() else default_rule_engine

    # 2. Identity Resolver
    resolver = IdentityResolver(
        identities_path=identities_csv if identities_csv.exists() else DEFAULT_USER_IDENTITIES_CSV,
        audit_log_path=audit_log_csv if audit_log_csv.exists() else DEFAULT_USER_AUDIT_LOG_CSV,
    )

    # 3. Evidence Ingestion
    logger.info("Loading and indexing evidence artifacts...")
    obs, cov, unparsed, counts = load_all_evidence()
    logger.info(
        "Loaded %d observations across %d snapshots (%d unparsed files)",
        len(obs),
        len(cov),
        len(unparsed),
    )

    # 4. Linker, Evaluator, Flow Detector
    linker = EvidenceLinker(
        observations=obs,
        activity_path=activity_csv if activity_csv.exists() else DEFAULT_SYSTEM_ACTIVITY_CSV,
        rule_engine=rule_engine,
    )
    evaluator = StateEvaluator(
        observations=obs,
        coverages=cov,
        rule_engine=rule_engine,
    )
    flow_detector = FlowRiskDetector(
        observations=obs,
        activity_path=activity_csv if activity_csv.exists() else DEFAULT_SYSTEM_ACTIVITY_CSV,
    )

    # 5. Intent Classifier
    intent_classifier = IntentClassifier()

    # 6. Composite Decision Engine
    engine = AuditDecisionEngine(
        resolver=resolver,
        linker=linker,
        evaluator=evaluator,
        flow_detector=flow_detector,
        rule_engine=rule_engine,
        intent_classifier=intent_classifier,
    )

    # 7. Read requests
    requests: list[dict[str, str]] = []
    with open(requests_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            requests.append(r)

    # Sort requests by case_id natural numeric order
    def case_sort_key(req: dict[str, str]) -> int:
        cid = req.get("case_id", "")
        parts = cid.split("_")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    requests.sort(key=case_sort_key)
    logger.info("Loaded %d requests in %.2fs", len(requests), time.time() - t0)

    return engine, requests


def run_pipeline(
    engine: AuditDecisionEngine,
    requests: list[dict[str, str]],
    output_path: Path,
    quiet: bool = False,
) -> None:
    """Execute audit across all requests and write output.csv atomically."""
    t0 = time.time()
    results: list[dict[str, str]] = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    total = len(requests)
    for idx, req in enumerate(requests, start=1):
        case_id = req["case_id"].strip()
        email = req["email"].strip()
        audit_at = _parse_iso(req["audit_at"].strip())
        reported_status = req.get("reported_status", "").strip() or None
        rep_at_str = req.get("reported_at", "").strip()
        reported_at = _parse_iso(rep_at_str) if rep_at_str else None
        request_text = req.get("request_text", "")

        res: CaseAuditResult = engine.audit_case(
            case_id=case_id,
            email=email,
            audit_at=audit_at,
            reported_status=reported_status,
            reported_at=reported_at,
            request_text=request_text,
        )

        status_counts[res.deletion_status] = status_counts.get(res.deletion_status, 0) + 1

        steps_dicts = [s.to_dict() for s in res.steps]
        steps_json = json.dumps(steps_dicts, separators=(",", ":"))

        results.append({
            "case_id": case_id,
            "deletion_status": res.deletion_status,
            "steps_json": steps_json,
        })

        if not quiet and (idx % 50 == 0 or idx == total):
            logger.info("Processed %d/%d cases (%.1f%%)...", idx, total, (idx / total) * 100)

    # Sort results strictly by case_id
    def res_sort_key(r: dict[str, str]) -> int:
        parts = r["case_id"].split("_")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    results.sort(key=res_sort_key)

    # Atomic write to temporary file then replace
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_output = output_path.with_suffix(".tmp")
    with open(temp_output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    temp_output.replace(output_path)
    elapsed = time.time() - t0

    logger.info("Successfully audited %d cases in %.2fs (%.1f ms/case)", total, elapsed, (elapsed / total) * 1000)
    logger.info("Final status distribution: %s", status_counts)
    logger.info("Completed predictions written to: %s", output_path)


def main() -> None:
    args = parse_args()
    if args.quiet:
        logger.setLevel(logging.WARNING)

    engine, requests = build_pipeline(args.dataset_dir)
    run_pipeline(engine, requests, args.output, quiet=args.quiet)


if __name__ == "__main__":
    main()
