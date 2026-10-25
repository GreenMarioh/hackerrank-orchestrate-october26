# HackerRank Orchestrate - October 2026: Ghost Data Still Exists

An AI-powered deletion-audit engine that verifies whether personal data was actually deleted across multi-store architectures, prevents recreation via synchronization and backup pipelines, and produces fully ordered remediation and verification plans.

**Challenge Link:** https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

---

## 1. Quick Start & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- Standard library dependencies (`sqlite3`, `csv`, `json`, `hashlib`, `re`, `dataclasses`, `pathlib`)
- Optional for tests: `pytest`

### Setup
```bash
# Clone repository
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26

# Create virtual environment and install test dependencies (optional)
python3 -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install pytest
```

### Running the End-to-End Pipeline
To run the full deletion-audit pipeline and generate `output.csv` at the repository root:

```bash
python3 code/main.py
```
*(On Windows: `.venv\Scripts\python code/main.py`)*

This reads all 518 cases from `dataset/deletion_requests.csv`, reconciles identities and historical mutations, evaluates multi-store databases and system activity at `audit_at`, and writes `output.csv` at the root.

### Validating Output Invariants
To verify schema conformity, step numbering, phase ordering, valid operations, and pre-audit evidence citations:

```bash
python3 code/tools/validate_output.py output.csv
```

### Running Test Suite
To run the complete unit and integration test suite:

```bash
pytest -q
```

---

## 2. Architecture Overview

The system is modularized under `code/ghost/`:

1. **`intent.py` (Intent Classifier):**  
   Evaluates `request_text` across multiple languages (English, German, French, Spanish, Japanese, Chinese) to determine if deletion was actually authorized. Correctly classifies non-deletion requests (marketing opt-out, data export/portability, invoice retrieval, email rectification) as `NOT_APPLICABLE` with `steps_json=[]`.
2. **`identity.py` (Historical Identity Resolver):**  
   Reconstructs the full identity timeline for each subject using `user_identities.csv` and `user_audit_log.csv`. Matches current and historical email addresses, phone numbers, full names, usernames, and SHA-256 email hashes.
3. **`ingest.py` (Evidence Ingestion & Pre-Indexing):**  
   Parses `evidence_files.csv` and discovers all structured records across `dataset/evidence/` (SQLite snapshots, JSON files, text dumps, and system logs). Normalizes schema fields across heterogeneous services.
4. **`linker.py` (Temporal Invariant Linker):**  
   Binds evidence records to identity clusters under strict temporal cutoff invariants (`captured_at <= audit_at` and `file_captured_at <= audit_at`). Assigns multi-tier confidence levels (`HIGH` for direct entity matches; `MEDIUM` for activity references).
5. **`rules.py` (Policy Categorization & Action Engine):**  
   Maps resource types to policy categories defined in `deletion_rules.csv` (`ACCOUNT_PROFILE`, `MARKETING_PROFILE`, `TAX_INVOICE`, `COMMUNICATION_LOG`, `ACCOUNT_TOMBSTONE`). Determines required actions (`DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`).
6. **`state.py` (Multi-Store Invariant State Determination):**  
   Evaluates whether data remains across primary, regional, reporting, or failover replicas. Enforces the invariant: **if any store still holds identified data at `audit_at`, the resource remains `PRESENT`**.
7. **`flows.py` (Active Flow & Restore Risk Detection):**  
   Analyzes `dataset/system_activity.csv` for replication workers, sync jobs, and backup pipelines. Identifies flows that can recreate deleted records (`REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`).
8. **`planner.py` & `decision.py` (Remediation Planner & Decision Engine):**  
   Constructs the final audit decision:
   - `NOT_APPLICABLE`: Non-deletion requests.
   - `COMPLETE`: All prohibited records deleted/redacted, retained records present, and no active flows. Emits evidence-backed verification steps proving the compliant state.
   - `INCOMPLETE`: Any remaining record, unredacted PII, or active flow. Emits findings, ordered remediation steps (`DISABLE_DATA_FLOW` before `DELETE_RECORD`), and post-remediation verification checks.

---

## 3. Assumptions & Limitations

1. **Evidence Citations:** Finding steps and `COMPLETE` verification steps strictly cite participant-visible evidence captured at or before `audit_at`. Proposed remediation and future verification steps for `INCOMPLETE` cases use `evidence_id=""`.
2. **Confidence Gating:** Violation findings require `HIGH` confidence (direct entity match). This prevents background worker noise and decoy activity in `system_activity.csv` from generating spurious violation findings.
3. **Image / Document OCR:** Production runtime relies on deterministic metadata and structured text/SQL evidence. Image files (`.png`) in evidence are treated via companion text manifests or activity entries unless external vision models are configured.
4. **No Golden Shortcuts:** Production code never reads or inspects `sample_output.csv` or `sample_deletion_requests.csv`. All predictions are derived strictly from first principles and policy rules.

---

## 4. Deliverables & Packaging

The submission package consists of:
- `code.zip`: Contains `code/`, `evaluation/`, `README.md`, `AGENTS.md`.
- `output.csv`: The root-level predictions file containing 518 data rows.
- `log.txt`: The append-only transcript of agent turns.
- `code/evaluation/evaluation_report.md`: Detailed accuracy analysis, methodology, and 3 custom test cases.
- `code/evaluation/usage_report.md`: Computational benchmarks and zero-cost model usage summary.
