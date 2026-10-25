# Usage Report: Ghost Data Still Exists (Full Dataset Execution)

**Challenge:** HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*  
**Execution Scope:** Full Evaluation Dataset (`dataset/deletion_requests.csv`), 518 Requests.  
**Output Artifact:** Root `output.csv` (SHA-256: `4dc4e5c911f463409f84c2f74c5e191e2ee818921cdba4313d201d8f385ec2a1`)  
**Pipeline Entry Point:** `code/main.py`  
**Execution Environment:** Python 3.12 (Native Deterministic Engine)  
**Date:** October 25, 2026  

---

## 1. System Architecture & Model Providers

The production audit system is architected as a fully deterministic, high-throughput, rule-directed deletion-audit agent. All evidence ingestion, multi-identifier resolution, temporal graph linking, replica drift comparison, policy categorization, and remediation planning are executed locally via compiled Python routines without external network calls or non-deterministic stochastic APIs.

- **Model Providers:** Local Deterministic Rule-Engine / Graph Traversal Engine (Native Python)
- **Model Names:** `ghost-audit-deterministic-v1`
- **External LLM Runtime API Calls:** **0**
- **External Cloud API Endpoints:** None

---

## 2. Token Usage & Model Calls Summary

| Metric | Measured Value |
|---|---|
| **Total Evaluation Requests** | 518 cases |
| **Total Model API Calls** | 0 calls |
| **Input Tokens** | 0 tokens |
| **Output Tokens** | 0 tokens |
| **Total Tokens** | 0 tokens |
| **Average Tokens per Request** | 0.0 tokens/case |
| **Total Model Cost (USD)** | **$0.0000** |
| **Average Cost per Request (USD)** | **$0.0000** |

---

## 3. Computational Performance & Runtime Throughput

A clean end-to-end execution of `code/main.py` processing all 518 cases and writing `output.csv` was measured and benchmarked:

- **Total Execution Time:** **52.33 seconds**
- **Average Latency per Case:** **101.0 ms / case**
- **Peak Memory Usage:** ~185 MB RSS
- **Throughput:** ~9.9 cases / second

### Breakdown by Execution Phase:
1. **Evidence & Graph Ingestion (one-time global pre-indexing):** ~13.1 seconds
   - Ingests `evidence_files.csv`, parses 32 SQLite database snapshots, ingests structured JSON/text records, and indexes 1,480 system activity events.
2. **Identity History Expansion:** ~0.9 seconds
   - Resolves all 518 target subjects across `user_identities.csv` and historical mutation events in `user_audit_log.csv`.
3. **Temporal Invariant Linking & State Audit:** ~34.2 seconds
   - Evaluates multi-store replica drift (`account_primary`, `account_regional_replica`, `account_failover_replica`, `reporting_replica`) per subject at case-specific `audit_at` cutoff.
4. **Remediation Planning, Sorting & CSV Emission:** ~4.1 seconds
   - Applies policy constraints from `deletion_rules.csv`, ensures dependency ordering (`DISABLE_DATA_FLOW` before `DELETE_RECORD`), formats steps into strict JSON schema, and emits root `output.csv`.

---

## 4. Output Summary Across the 518 Cases

- **Total Processed Rows:** 518
- **Status Distribution:**
  - `INCOMPLETE`: **348** (67.18%)
  - `COMPLETE`: **160** (30.89%)
  - `NOT_APPLICABLE`: **10** (1.93%)
- **Total Generated Audit Steps:** **2,540 steps**
  - Average Steps per Case: **4.90 steps**
  - Finding Steps: 692
  - Remediation Steps: 692
  - Verification Steps: 1,156
- **Schema & Invariant Compliance:** 100% verified via `code/tools/validate_output.py`.
