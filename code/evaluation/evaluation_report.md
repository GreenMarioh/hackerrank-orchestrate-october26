# Evaluation Report: Ghost Data Still Exists (Phase 9 Audit)

**Challenge:** HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*  
**Evaluation Scope:** 32 Sample Deletion Requests (`sample_deletion_requests.csv`) vs Ground Truth (`sample_output.csv`), and Full Dataset Invariant Audit across 518 Evaluation Cases (`deletion_requests.csv`).  
**Audit Engine:** Deterministic Multi-Store Deletion Audit Engine (`code/main.py`).  
**Date:** October 25, 2026  

---

## 1. Executive Summary & Core Metrics

The deletion-audit system implements an end-to-end evidence-based pipeline that verifies whether personal data was truly deleted across multi-store architectures (primary databases, regional replicas, reporting replicas, failover replicas, logs, backups, and data synchronization flows).

Across all 32 public sample cases with ground-truth labels:
- **Case-Level Deletion-Status Accuracy:** **32 / 32 (100.0%)**
- **Phase Ordering Compliance:** **32 / 32 (100.0%)** (strict `FINDING` -> `REMEDIATION` -> `VERIFICATION` order)
- **Step Resource Alignment Recall:** **158 / 193 (81.87%)**
- **Operation Accuracy on Aligned Steps:** **152 / 158 (96.20%)**
- **Citation Temporal Accuracy on Aligned Steps:** **158 / 158 (100.0%)** (zero pre-audit evidence leakage)
- **Exact Step-List Match (full steplist identical to sample):** **5 / 32 (15.63%)**
- **Exact Step Dictionary Match:** **95 / 193 (49.22%)**

---

## 2. Methodology & Denominators

### 2.1 Evaluation Framework
The evaluation was conducted using an independent validation harness (`code/tools/audit_samples.py`) that strictly separates test harnesses from production prediction logic. The production pipeline (`code/main.py` and `code/ghost/*`) never imports or inspects `sample_output.csv` or `sample_deletion_requests.csv`.

### 2.2 Metric Definitions & Explicit Denominators
1. **Case-Level Status Accuracy:** Fraction of cases where predicted `deletion_status` (`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`) exactly matches ground truth.
   - Denominator: **32 cases**.
   - Result: 32 / 32 = **100.0%**.
2. **Phase Ordering Compliance:** Fraction of cases adhering to consecutive step numbering (1..N) and monotonically non-decreasing phase progression (`FINDING` -> `REMEDIATION` -> `VERIFICATION`).
   - Denominator: **32 cases**.
   - Result: 32 / 32 = **100.0%**.
3. **Step Resource Alignment Recall:** Fraction of ground-truth steps whose `(phase, system_id, resource_id)` appears in the generated plan.
   - Denominator: **193 expected steps**.
   - Result: 158 / 193 = **81.87%**.
4. **Operation Accuracy on Aligned Steps:** Fraction of aligned steps whose `operation` exactly matches the ground truth.
   - Denominator: **158 aligned steps**.
   - Result: 152 / 158 = **96.20%**.
5. **Citation Temporal Accuracy:** Fraction of aligned steps where the cited `evidence_id` was captured at or before `audit_at`.
   - Denominator: **158 aligned steps** (with 100% of generated steps passing root-level invariant checks).
   - Result: 158 / 158 = **100.0%**.
6. **Exact Step Dictionary Match:** Fraction of ground-truth steps where every field (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`) matches an identical step in the generated output.
   - Denominator: **193 expected steps**.
   - Result: 95 / 193 = **49.22%**.

---

## 3. Detailed Mismatch Breakdown & Root-Cause Analysis

While case-level status accuracy is 100% (all 10 `COMPLETE` and 22 `INCOMPLETE` correctly classified), exact step-list equivalence is 15.63%. Detailed investigation revealed four structural reasons:

### 3.1 Deleted Primary Account Verification (High-Confidence Policy Gate)
- **Observation:** In sample cases `case_01`, `case_02`, `case_04` (COMPLETE) and post-remediation steps in `case_06`, `case_07`, `case_08`, `case_10`, `case_22`, `case_32`, the ground truth includes `VERIFY_RECORD_ABSENT` for `account_service / account_XXXX` citing `evidence_54` or empty string.
- **Root Cause:** When an account has already been cleanly expunged from all database tables before `audit_at`, no direct profile record appears in the SQL dumps. The candidate link is recovered solely from deletion worker activity in `system_activity.csv` (`confidence="MEDIUM"`).
- **Design Rationale:** To prevent hundreds of decoy/unrelated background worker activities in `system_activity.csv` from generating spurious violation findings across the 518 full evaluation cases, the engine requires `confidence="HIGH"` (direct entity match) to generate findings or post-deletion verifications. Relaxing this would introduce false positives across decoy users.

### 3.2 Evidence Export Bundle Scope vs Global Store Verification
- **Observation:** In `case_21` (COMPLETE), the ground truth lists 3 verification steps for `account_service`, `analytics_platform`, and `security_service`. The production pipeline generated 7 verification steps, discovering 4 legal service records (`doc_evidence_27_*` in `evidence_27`) that underwent compliant redaction.
- **Root Cause:** Ground truth in `sample_output.csv` focuses verification specifically on the primary export bundle (`evidence_92` / `evidence_54`), whereas full cross-system discovery traces all evidence files linked to the user's historical identifiers.

### 3.3 System-Level Log Observations (`account_service`)
- **Observation:** In cases `case_12`, `case_17`, and `case_19`, the generated output includes finding/remediation steps for `resource_id="account_service"`.
- **Root Cause:** `evidence_01` (service log) records an error `Failed to delete account_service for user_...`. The engine parsed this as a distinct remaining resource log.

### 3.4 Multi-Store Replica Drift Verification
- **Observation:** Across multi-store drift cases (`case_11`, `case_13`, `case_16`), the pipeline achieved **100% exact step-list match**. The engine correctly isolated replica tables (`account_primary` vs `account_failover_replica`), detected unpurged replica rows, and ordered remediation steps correctly.

---

## 4. Participant-Created Evaluation Cases

To rigorously test edge cases beyond the 32 samples, three comprehensive evaluation test cases were designed and tested against the engine.

### Test Case 1: Active Sync Pipeline Recreating Deleted Data (Replication Drift)
- **Scenario Description:** User requests deletion. The primary database successfully drops the user record at `2026-09-10 10:00:00`. However, a legacy sync process `user_sync_worker` reads from an unpurged reporting replica and writes back to an analytics cache at `2026-09-10 10:15:00`. Audit cutoff is `2026-09-10 12:00:00`.
- **Input Attributes:**
  - `case_id`: `custom_case_001`
  - `email`: `marcus.vance@example.net`
  - `request_text`: "Please permanently delete my account and all associated personal data under GDPR Article 17."
  - `reported_status`: `COMPLETE` (workflow claims complete)
  - `audit_at`: `2026-09-10T12:00:00Z`
- **Ground Truth & Expected Output:**
  - `deletion_status`: `INCOMPLETE`
  - `steps`:
    1. `FINDING`: `REPORT_ACTIVE_DATA_FLOW` on `sync_service / user_sync_worker` (`ACTIVE`, citing sync log)
    2. `FINDING`: `REPORT_REMAINING_RECORD` on `analytics_cache / cache_marcus_vance` (`PRESENT`)
    3. `REMEDIATION`: `DISABLE_DATA_FLOW` on `sync_service / user_sync_worker` (`DISABLED`)
    4. `REMEDIATION`: `DELETE_RECORD` on `analytics_cache / cache_marcus_vance` (`ABSENT`)
    5. `VERIFICATION`: `VERIFY_DATA_FLOW_DISABLED` on `sync_service / user_sync_worker` (`DISABLED`)
    6. `VERIFICATION`: `VERIFY_RECORD_ABSENT` on `analytics_cache / cache_marcus_vance` (`ABSENT`)
- **Justification:** Tests pipeline precedence: data flows must be disabled before remediating downstream records to prevent immediate recreation.

### Test Case 2: Multi-Language Non-Deletion Portability Request
- **Scenario Description:** A user submits a request in German asking for a copy of their transaction history and data export under GDPR Article 20, explicitly stating they want to keep their account active.
- **Input Attributes:**
  - `case_id`: `custom_case_002`
  - `email`: `helena.schmidt@beispiel.de`
  - `request_text`: "Bitte senden Sie mir eine vollständige Kopie meiner Daten und Transaktionshistorie gemäß Art. 20 DSGVO. Ich möchte mein Konto nicht löschen."
  - `reported_status`: `NOT_STARTED`
  - `audit_at`: `2026-09-15T08:00:00Z`
- **Ground Truth & Expected Output:**
  - `deletion_status`: `NOT_APPLICABLE`
  - `steps`: `[]` (empty JSON array)
- **Justification:** Verifies the intent classification engine handles multi-lingual GDPR requests and respects explicit negation ("nicht löschen" / do not delete), preventing unauthorized account deletion.

### Test Case 3: Retained Financial Record under Legal Obligation vs Prohibited Direct PII
- **Scenario Description:** User requests full account erasure. The user has tax invoices retained under a 7-year statutory retention rule (`deletion_rules.csv` category `TAX_INVOICE` -> action `REDACT`). The billing system has an invoice `inv_2024_981` that retains transaction amount and date, but still displays the user's personal phone number and home address.
- **Input Attributes:**
  - `case_id`: `custom_case_003`
  - `email`: `elena.rostova@example.org`
  - `request_text`: "Delete all my personal records immediately."
  - `reported_status`: `COMPLETE`
  - `audit_at`: `2026-09-20T14:00:00Z`
- **Ground Truth & Expected Output:**
  - `deletion_status`: `INCOMPLETE`
  - `steps`:
    1. `FINDING`: `REPORT_EXPOSED_PII` on `billing_service / inv_2024_981` (`PRESENT`, citing invoice PDF)
    2. `REMEDIATION`: `REDACT_RECORD` on `billing_service / inv_2024_981` (`REDACTED`)
    3. `VERIFICATION`: `VERIFY_RECORD_REDACTED` on `billing_service / inv_2024_981` (`REDACTED`)
    4. `VERIFICATION`: `VERIFY_RECORD_PRESENT` on `billing_service / inv_2024_981` (`PRESENT`)
- **Justification:** Verifies rule-directed treatment: legal retention records must NOT be deleted (`DELETE_RECORD`), but exposed PII must be redacted, followed by verification of redaction and retention.

---

## 5. Failures Found and Improvements Made

1. **Temporal Evidence Leakage in Multi-Store Evidence:**
   - *Failure:* During initial development, observations from evidence files captured after `audit_at` (e.g. `evidence_12`, `evidence_31`) were linked to cases whose audit cutoff preceded the snapshot time, causing invalid citations.
   - *Fix:* Enforced strict two-layer temporal filtering in `code/ghost/linker.py` checking both `obs.captured_at <= audit_at` and `obs.file_captured_at <= audit_at`.
2. **Decoy Activity Disambiguation:**
   - *Failure:* Background activity logs in `system_activity.csv` contain hundreds of automated garbage collector runs and unrelated tenant actions. Low-confidence matching caused false-positive findings.
   - *Fix:* Implemented multi-tier confidence gating in `code/ghost/linker.py`. Violations require direct entity matching (`HIGH` confidence) to transition a case to `INCOMPLETE`.
3. **Intent Classification Negation Handling:**
   - *Failure:* Keyword-based matching falsely tagged requests containing "do not delete my account, only update my email" as deletion requests.
   - *Fix:* Implemented comprehensive negation patterns and multi-lingual regular expressions in `code/ghost/intent.py` across English, German, French, Spanish, Japanese, and Chinese.
