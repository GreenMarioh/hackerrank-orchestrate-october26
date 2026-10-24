# Ghost Data Still Exists — Build Plan and Antigravity Workflow

Hand this file to Antigravity as the master plan. Place it at the repo root (next to `AGENTS.md`) and tell the agent to read it first.

Conventions used below:
- **[VERIFIED]** means it was checked against the real dataset files.
- **[HYPOTHESIS]** means it is a plausible reading that Phase 1 must confirm or reject with a test. Do not build on a hypothesis before its test passes.
- All terminal commands are PowerShell, run from the repo root.

---

## 0. Ground rules (apply to every phase)

1. Read `AGENTS.md` and `problem_statement.md` first. Follow the `AGENTS.md` logging contract (`log.txt`, with real `tool=` and `model=` values) for every turn. Never log secrets.
2. Production logic may read only the files under `dataset/`.
   - `sample_output.csv` and `sample_deletion_requests.csv` are for development and evaluation only. They must never be read by `code/main.py`'s prediction path.
   - No hardcoded case IDs, user IDs, resource IDs, emails or evidence IDs anywhere in `code/`.
   - No "case family" shortcuts keyed on specific values.
3. Use only information at or before each case's `audit_at`: evidence with `captured_at` ≤ `audit_at`, activity with `event_time` ≤ `audit_at`.
4. `reported_status` and `reported_result` are claims, not proof.
5. Output must be deterministic: same input gives byte-identical `output.csv`. Sort everything, set seeds, use temperature 0 for any model call.
6. Secrets come only from environment variables or an uncommitted `.env`.
7. The judge ignores `.csv`, `.json`, `.sql` and `.log` files. Put every metric, custom test case, and token figure **inside the Markdown reports**, and keep test fixtures as `.py` files.
8. Keep prompts in source (`.py`) or `.md` files, not only in JSON.
9. Do not add heavyweight frameworks. Use the standard library plus a few small packages.

---

## 1. What the dataset actually contains

### 1.1 Verified facts

| Area | Fact |
| --- | --- |
| Requests | 518 rows, unique `case_id`, no nulls. Dates are consistent (requested ≤ reported ≤ audit). `reported_status`: COMPLETE 254, PARTIALLY_COMPLETE 152, NOT_STARTED 112. [VERIFIED] |
| Case IDs | Look like `case_33`, `case_100`. Sorting as plain strings puts `case_100` before `case_33`. Check `sample_output.csv`: its order is `case_01…case_32`. Decide the sort rule from the spec ("sorted by `case_id`") and the template file `dataset/output.csv`, and test it. [VERIFIED that the issue exists] |
| Emails | 20 request emails have uppercase letters. Normalize with strip + lowercase. [VERIFIED] |
| Duplicate subject | `ingrid.dahl@outlook.com` appears in `case_33` and `case_52` with different `audit_at`. The answer must depend on `audit_at`. [VERIFIED] |
| Historical emails | 100 of 518 request emails match only a historical email in `user_audit_log.csv`. In all 100 the change happened before `audit_at`. [VERIFIED] |
| Hashes | `email_hash` = SHA-256 of the lowercased email, for 100% of `user_identities.csv`. Every hash in the audit log is explained by a known email. So historical hashes can be computed from historical emails. [VERIFIED] |
| Names | 6 users share names with other users. Never match by name alone. [VERIFIED] |
| Languages | Request text appears in English, Portuguese, Spanish, Korean, Japanese and French. [VERIFIED] |
| Non-deletion | 10 main-file requests are one-off non-deletion asks (marketing opt-out, data download, email change, surname fix, login help, invoice copy, etc.). `system_activity.csv` has exactly 10 `CLASSIFY_REQUEST` events saying "classified as non-deletion". [VERIFIED counts; per-case mapping is a HYPOTHESIS] |
| Samples | 32 cases: 22 INCOMPLETE, 10 COMPLETE, 0 NOT_APPLICABLE. 11 of 17 cases reported `COMPLETE` are truly INCOMPLETE. [VERIFIED] |
| Rules | 15 rules in `deletion_rules.csv` (see §4.1). [VERIFIED] |
| Activity | 4,011 events, 17 event types. `reported_result`: SUCCESS 2,914, FAILED 721, PARTIAL 376. Only 12 `LINK_RESOURCE_IDENTITY` events exist. [VERIFIED] |
| Evidence | 94 files: 28 JSON, 26 log, 24 SQL, 11 PNG, 4 PDF, 1 TXT. Manifest does not name the case or user. [VERIFIED] |
| Ordering rule | Sorting steps by (operation order from the spec table, then `system_id`, then `resource_id`) reproduces the step order of **all 32** sample answers. `step_no` is consecutive from 1. [VERIFIED] |
| Prefix → `system_id` | Seen in samples: `account_`→`account_service`, `search_`→`search_service`, `support_`→`support_platform`, `analytics_`→`analytics_platform`, `audit_record_`→`security_service`, `backup_`→`backup_service`, `data_flow_`→`integration_service`, `export_`→`export_service`, `tombstone_`→`identity_service`. [VERIFIED] |
| Replica ≠ system_id | In `case_05`, the record is only in a failover replica, yet the answer uses `system_id=account_service`. So `system_id` is the logical service, not the replica name. [VERIFIED] |
| INCOMPLETE content | INCOMPLETE sample answers include verification steps for already-compliant resources too (e.g. 40 `VERIFY_RECORD_ABSENT` against only 21 `DELETE_RECORD`; 17 `VERIFY_RECORD_PRESENT`). [VERIFIED] |
| Evidence IDs | 118 step evidence IDs in the samples are empty (remediation and future verification). Findings and COMPLETE verifications cite one. [VERIFIED] |

### 1.2 Hypotheses to test in Phase 1

- **H1 (linking window).** Activity events for a case's resources fall within about 2 hours of the case's `reported_at`. In the samples, 100% of the 88 events on expected resources fell within ±120 minutes, but only 32% within ±30 minutes. This is a *candidate-generation* heuristic only. It is not enough on its own, because a window contains ~4 unrelated events on average.
- **H2.** Records that have been anonymized (null `user_id`, email, phone) can only be linked through activity events, catalog links, or other evidence. Find which.
- **H3.** `LINK_RESOURCE_IDENTITY` events and attachment-catalog events carry authoritative resource ownership.
- **H4.** `RETAIN_RECORD` events and PDFs (retention register, compliance extract) give the retention evidence for audit records and legal holds.
- **H5.** The prefix → category mapping in §4.2 for prefixes not yet seen in samples (`cache_`, `email_delivery_`, `marketing_`, `object_`, `legal_hold_`).
- **H6.** An evidence file is "relevant" to a case only through content links (email, historical email, hash, `user_id`, resource ID), never through the manifest.
- **H7.** A replica holding a record that the primary no longer has counts as "remaining record" (this is how `case_05` behaves).

---

## 2. Architecture

**Deterministic core, narrow LLM use.** The grader compares exact operations, resource IDs, step order and evidence IDs. A model that hallucinates one ID costs more than it gains, so everything that can be rules is rules.

LLM is used only for:
1. **Request intent** (deletion vs non-deletion), multilingual. Cache by request text (~375 unique texts in the main file). Cross-check against `CLASSIFY_REQUEST` activity. Disagreements are logged, not silently resolved.
2. **PNG screenshots** (11 files): vision extraction into a fixed JSON schema.
3. Optional fallback for a PDF whose text extraction fails.

Everything else (identity, linking, state, rules, ordering, serialization) is plain Python.

```
dataset/*.csv, dataset/evidence/**
        │
        ▼
 ingestion  ──►  Observation store  ──►  identity resolver
 (sql/json/log/pdf/png/txt)                    │
        │                                      ▼
        └──────────►  evidence linker  ──►  per-case Resource States
                                               │
                    rules engine (deletion_rules.csv) ◄─┤
                                               │
                    flow / restore analyzer ◄──┤
                                               ▼
                       status classifier + step planner
                                               ▼
                    serializer + validator  ──►  output.csv
```

### 2.1 Folder layout

```
code/
  main.py                      # CLI entry: python code\main.py
  README.md?                   # (README.md goes at zip root; see §8)
  ghost/
    config.py                  # paths, constants, model names (from env)
    models.py                  # dataclasses: Case, Identity, Observation, ResourceState, Step
    ingest/
      loader_csv.py
      loader_sql.py            # runs sqlite3 in memory on each .sql file
      loader_json.py
      loader_logs.py           # several log dialects
      loader_pdf.py            # pypdf / pdfplumber (pure Python, no poppler)
      loader_image.py          # vision call + cache
      loader_txt.py
    identity.py                # alias resolution
    linker.py                  # evidence → case
    state.py                   # resource state at audit_at
    rules.py                   # deletion_rules.csv → category/action
    flows.py                   # data-flow + restore analysis
    intent.py                  # deletion vs non-deletion
    planner.py                 # status + steps
    serialize.py               # CSV/JSON writer + validator
    llm.py                     # thin client + usage tracker (only place that calls a model)
  prompts/
    intent.md
    image_extract.md
  evaluation/
    main.py                    # evaluation harness
    metrics.py
    custom_cases.py            # synthetic extra cases (python, not csv/json)
    evaluation_report.md       # written results
    usage_report.md            # token/cost results
  tools/
    profile_dataset.py         # Phase 1 profiling and hypothesis tests
  tests/
    test_*.py
requirements.txt
```

---

## 3. Step-by-step build

Each phase lists: tasks, files, tests, and the **done criteria**. Do not start the next phase until the done criteria pass. After each phase, run the sample evaluation (Phase 9's harness, once it exists) and record the result.

### Phase 0 — Environment

Tasks:
1. Create the venv at the repo root (outside `code/`):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install pypdf pdfplumber pillow pytest
   pip install google-genai   # only if using Gemini; or the SDK of the chosen provider
   pip freeze > code\requirements.txt
   ```
   Review `requirements.txt` afterwards and keep only what the code imports.
2. Add `.gitignore`: `.venv/`, `__pycache__/`, `.env`, `.cache/`, `*.zip`.
3. Create `.env.example` with the variable *names* only (e.g. `LLM_API_KEY=`, `LLM_MODEL=`). Never commit a real key.
4. Check optional tools: `tesseract --version`. If missing, skip OCR and rely on the vision model for PNGs.

Done when: `python -c "import pypdf, pdfplumber, PIL"` runs, and `pytest` runs (even with zero tests).

### Phase 1 — Dataset profiling and hypothesis tests

File: `code/tools/profile_dataset.py`. It prints a report and exits non-zero if a *required invariant* fails.

Tasks:
1. Re-verify every [VERIFIED] row in §1.1 with code, so the facts are reproducible.
2. Inventory every evidence file: type, size, captured_at, number of records, tables and columns (SQL), top-level keys (JSON), line formats (logs), page count and extracted text length (PDF), image size (PNG).
3. Parse every SQL file with `sqlite3` (`executescript` into `:memory:`). List tables per file and note topology (primary, regional replicas, reporting replica, failover replica) from the header comment.
4. Parse the log dialects. At least three exist (plain `key=value` lines, syslog-style `<12>1 ...`, and cloud-runtime lines whose `message="..."` field has escaped quotes). Write one tokenizer per dialect, and a test using one sample line of each.
5. Extract every PDF's text. Note which carry user IDs, retention dates, subject references.
6. Look at all 11 PNGs (view them) and write down what each shows, before designing the extraction schema.
7. Test H1–H7 (§1.2). For each, report support and counter-examples on the 32 samples.
8. Build the **case → expected-resource table for the samples** from `sample_output.csv` (development only), and for each expected resource record where its identity link comes from (evidence file, activity row, catalog event, time window). This table tells you which link types the linker must support.
9. List decoys: emails, resource IDs and names that look like the subject but are not (e.g. several different "Thandiwe" emails exist).

Deliverable: `docs/dataset_profile.md` (or in `evaluation/evaluation_report.md`, appendix) with the results.

Done when: every hypothesis is marked CONFIRMED / REJECTED / PARTIAL, and the link types needed are listed.

### Phase 2 — Ingestion into a normalized Observation store

Define in `models.py`:

```python
@dataclass(frozen=True)
class Observation:
    obs_id: str            # deterministic, e.g. f"{file_id}:{table_or_path}:{resource_id}"
    file_id: str           # evidence_NN (or activity_/audit_ for non-file sources)
    captured_at: datetime  # best timestamp for this observation (see below)
    system_id: str         # logical service (account_service, search_service, ...)
    store: str             # primary | regional_replica | reporting_replica | failover_replica | export | log | doc | image
    resource_id: str
    category: str | None   # filled by rules.py
    fields: dict           # normalized fields: user_id, emails[], phones[], email_hash, name, status,
                           # restore_allowed, enabled, retain_until, ...
    present: bool          # the snapshot shows the record exists
```

Rules for time: use the most specific timestamp available (inner snapshot `captured_at` in JSON bundles; the SQL header `Captured at`; the row's `updated_at` only if it is the capture time; log line time). Fall back to the manifest `captured_at`. **Drop any observation later than the case's `audit_at` when evaluating that case.**

Tasks:
1. `loader_sql.py`: for each table, produce one Observation per row. Parse `record_json` columns as JSON and flatten. Mark `store` from the table name and header topology.
2. `loader_json.py`: handle both shapes seen so far — bundles with a `snapshots` list (`data_store`, `collection`, `records`, per-snapshot `captured_at`) and single-collection exports (`captured_at`, `source`, `collection`, `records`), plus `service_resource_export` files that nest by service (`backup_service.archives`, `export_service.exports`, `integration_service.connectors`, …). Write the loader to walk generically for objects having a `resource_id`, carrying down the nearest enclosing `data_store`/`collection`/`captured_at`. Never assume a fixed key list; log unknown shapes.
3. `loader_logs.py`: one Observation per log line that carries a `resource_id` or identifier (`correlation_key`, `lookup_key`, `match_key`, `matched_value`, `owner_email`, …). Keep event name, level, and timestamp. Treat logs as supporting evidence of exposure (e.g. a PII scan hit).
4. `loader_pdf.py`: extract text page by page; parse "Record / Detail" rows, `user_NN`, emails, `resource` and `audit_record_*` references, retention dates ("Retain until ..."), order/statement numbers.
5. `loader_image.py`: send each PNG to the vision model with `prompts/image_extract.md`, requesting strict JSON (fields visible: record IDs, user IDs, emails, phones, statuses, toggles like "enabled/disabled", "restore allowed", timestamps). Cache by SHA-256 of the file bytes under `.cache/` (not shipped). Temperature 0. If no key is set, skip images and log a clear warning.
6. `loader_txt.py`: same text parsing as PDFs.
7. Activity and audit-log loaders produce Observations with `file_id=activity_id` or `audit_id`.

Tests: one fixture per format (small, hand-written in `tests/fixtures.py`), asserting the exact Observations produced. Add a test that every SQL file parses, and that every evidence file in the manifest produces at least one Observation or an explicit "unparsed" note.

Done when: all 94 files load, with a coverage table (files → observation counts), and zero silent failures.

### Phase 3 — Identity resolution

File: `identity.py`. Input: request email. Output: `Identity` with:
- `user_id`
- all emails ever used (current + historical from `user_audit_log.csv`, lowercased, stripped)
- all phones (current + historical)
- all email hashes (SHA-256 of each known email; also the stored hashes)
- name (informational only; never used alone to match)
- the match type (`current_email` or `historical_email`) and the audit-log rows used (their `audit_id`s — these are citable evidence IDs)

Logic:
1. Normalize the request email. Look for it in current `user_identities.csv`; else in `old_value`/`new_value` of audit-log email rows. Handle chains (A→B→C) by following the `user_id`.
2. If an email maps to more than one user, mark the identity AMBIGUOUS and do not guess; add the case to a review list and take the conservative path described in §5.
3. Build the alias set with all values the user ever had.
4. Honor time: audit-log changes after `audit_at` do not affect that case (none seen so far, but test for it).

Tests: current email, uppercase email, historical email (one-hop and multi-hop), duplicate-subject (`case_33` vs `case_52`), unknown email.

Done when: all 518 request emails resolve to exactly one `user_id`, and the 100 historical ones resolve through the audit log.

### Phase 4 — Rules engine and resource categorization

File: `rules.py`. Parse `deletion_rules.csv` into a table (`data_category`, `condition`, `required_action`). The **condition** column is prose; implement each as an explicit predicate on observed fields, with the rule ID in a comment. Do not use an LLM to evaluate conditions at run time.

Map each resource to a category using, in order: (1) the collection/table/`data_store` name in the observation, (2) the resource ID prefix, (3) activity `event_type` and `target_system`. Confirm `cache_`, `email_delivery_`, `marketing_`, `object_`, `legal_hold_` against real evidence (H5), then record the confirmed table in `rules.py` with a comment on how each mapping was verified.

Per-category required end-state (from §4.1) drives everything downstream.

Tests: one unit test per rule (15), each with a present-compliant, present-violating, and absent case.

Done when: every resource observed in any evidence file gets a category or an explicit `UNCATEGORIZED` flag, and the UNCATEGORIZED list is empty or explained.

### Phase 5 — Evidence linking (the hard part)

File: `linker.py`. Goal: for a case, find every resource belonging to the identity.

Link strategies, in strength order (stop being strict only when documented):
1. **Direct identifier match** in an observation: any of the user's emails, phones, hashes, `user_id` (as `user_id`, `customer_reference`, `subject_reference`, `owner_email`, `customer_email`, …). Compare case-insensitively, normalized phone digits.
2. **Catalog/link events:** `LINK_RESOURCE_IDENTITY` and attachment-catalog events in `system_activity.csv` name a resource and its owner explicitly.
3. **Resource-ID bridging:** a resource linked in 1 or 2 also appears in other evidence or activity without the identifier (for example an anonymized record that earlier carried the user). Follow the same `resource_id` across snapshots.
4. **Time-window candidates:** for resources that only appear in activity (e.g. a deleted account with just a `DELETE_RECORD` event), use events near the case's `reported_at` as *candidates*, then confirm using a second signal (same system family as other linked resources, consistent event sequence such as DELETE then SYNC, no other claimant). If only the window supports a resource, include it only when there is no competing claimant, and log it as "low-confidence link" so it can be audited.
5. **Never** link by name alone or by manifest alone.

Anti-leak: while linking, drop observations after `audit_at`.

Output: `CaseContext` with the identity, all linked resources with their link evidence, and a list of low-confidence links.

Development use of samples: for each of the 32 samples, compare the linked resource set with the resources in `sample_output.csv`. Report precision and recall of resource linking separately from status accuracy. Tune only generic parameters (window size, tie-breaking), never case-specific values.

Done when: on the samples, linking recall is 100% or every miss is explained by a generic, documented limitation. Precision is reported.

### Phase 6 — Resource state at `audit_at`

File: `state.py`. For each linked resource, compute one state from the observations at or before `audit_at`:

| State | Meaning |
| --- | --- |
| `PRESENT_IDENTIFIED` | The record exists and shows direct identifiers (email, phone, name, hash) or an attributable `user_id`. |
| `PRESENT_REDACTED` | The record exists with the stable `user_id` only; no direct identifiers. |
| `PRESENT_ANONYMIZED` | The record exists with no link to the user at all. |
| `ABSENT` | A snapshot that covers this store exists at or before `audit_at` and does not contain the record, in the primary **and every replica of that store captured by that evidence**. |
| `UNKNOWN` | No snapshot covers this store. Never assume absent or present. |

Rules:
- The latest observation at or before `audit_at` wins, per store. But **any** store (primary or replica) still holding identified data counts as a remaining copy (H7). Verify with the samples.
- Reported success in `system_activity.csv` does not set the state. It may only support a *hypothesis* that is then checked in the evidence.
- A resource that is ABSENT needs a citable snapshot (`file_id`) proving it. Record that file as the evidence for the verification step.
- Conflicts (two snapshots disagree): trust the later one before `audit_at`; log the conflict.

Done when: every linked resource gets a state with a cited observation, or `UNKNOWN` with a reason.

### Phase 7 — Data flows and restore paths

File: `flows.py`.

Signals to use, all from evidence first, activity second:
- Connectors/data flows: `enabled` true/false, status values like "stopped", `CHECK_DATA_FLOW` ("remains enabled"), `DISABLE_DATA_FLOW` events (a claim; confirm in a later connector snapshot).
- Backups: `restore_allowed` true/false, `CHECK_RESTORE_ACCESS` ("can still be restored"), `BLOCK_RESTORE` events (claim), `RESTORE_BACKUP` events (a restore job that "repopulated downstream resource X" proves a restore path is live and names the downstream record).
- Replication: `SYNC_RECORD` events and replica snapshots (a record in a replica after the primary deletion).

Per flow/backup produce: `ACTIVE`/`DISABLED`, `restore_allowed`/`BLOCKED`, with the supporting `file_id` or `activity_id`.

Retention interplay: backups fall under rule_14 (RETAIN if restore can be blocked), so the fix is to block restore, never to delete the archive.

Done when: for each sample with flow/restore steps, the detected flow/backup IDs match the expected resources.

### Phase 8 — Intent classification (NOT_APPLICABLE)

File: `intent.py`, prompt in `prompts/intent.md`.

1. First pass: keyword/regex signals per language for clear deletion verbs, and for clear non-deletion topics (marketing opt-out, export/download/access, correction, login, invoice). Use word-level patterns, but do not rely on them blindly, because "remove me from marketing lists *only*" contains a deletion verb and is a non-deletion request.
2. Second pass: the LLM classifies each **unique** request text with a strict JSON answer (`{"authorizes_deletion": true|false, "reason": "..."}`), temperature 0, one call per unique text, cached.
3. Combine: if rules and LLM agree, accept. If they disagree, use `CLASSIFY_REQUEST` activity for the case as a tiebreaker only when it can be linked to the case; otherwise take the conservative choice described in §5.2 and log it.
4. NOT_APPLICABLE short-circuits everything: `steps_json` is `[]`, and no deletion steps are produced.

Test with all 10 non-deletion texts, with the deletion paraphrases in 6 languages, and with tricky ones ("marketing lists only", "change the email", "download my data", and a deletion request that also asks for a copy first).

Done when: 100% on the labeled samples (note: the samples have no NOT_APPLICABLE, so test the 10 main-file non-deletion texts by reading them, and write your reading in the evaluation report as human-checked cases).

### Phase 9 — Planner (status and steps)

File: `planner.py`. For each deletion case with an identity and states:

**Per resource, derive required end state, current state, and the steps.**

| Category group | Required end state | If violating |
| --- | --- | --- |
| DELETE categories (profile, secondary identifier, search entry, cache, export, marketing, sole-owner attachment) | `ABSENT` | Finding `REPORT_REMAINING_RECORD`; remediation `DELETE_RECORD`; verification `VERIFY_RECORD_ABSENT` |
| REDACT categories (shared support message, email delivery log with an email, account tombstone) | `PRESENT_REDACTED` (tombstone keeps only `user_id`) | Finding `REPORT_EXPOSED_PII`; remediation `REDACT_RECORD`; verification `VERIFY_RECORD_REDACTED` |
| ANONYMIZE categories (analytics, telemetry attributable to a user) | `PRESENT_ANONYMIZED` | Finding `REPORT_EXPOSED_PII`; remediation `ANONYMIZE_RECORD`; verification `VERIFY_RECORD_ANONYMIZED` |
| RETAIN (audit log in retention period, active legal hold) | `PRESENT` | Verification `VERIFY_RECORD_PRESENT` (and see §5.3 if the record is missing) |
| Data flow | `DISABLED` | Finding `REPORT_ACTIVE_DATA_FLOW`; remediation `DISABLE_DATA_FLOW`; verification `VERIFY_DATA_FLOW_DISABLED` |
| Backup | `BLOCKED` (record kept) | Finding `REPORT_RESTORE_RISK`; remediation `BLOCK_RESTORE`; verification `VERIFY_RESTORE_BLOCKED` |

**Status**
- `NOT_APPLICABLE` if Phase 8 says no deletion authorization.
- `COMPLETE` if no violation, no active flow, no open restore path, and all required retained records are present.
- `INCOMPLETE` otherwise.

**Steps by status** (follow the spec; sample behavior confirmed in §1.1)
- `COMPLETE`: verification steps only, one per relevant resource for its required end state, each citing the evidence that proves it.
- `INCOMPLETE`: all findings (each citing evidence); then remediation for every violating resource and flow; then verification for the required final state of **every relevant resource, including those already compliant** (this is what the samples show). Remediation and verification steps carry `evidence_id: ""`.
- `NOT_APPLICABLE`: `[]`.

**Ordering**: sort the full list by (phase order, operation order from the spec table, `system_id`, `resource_id`). Sorting reproduces all 32 sample orders.
- Check the `AGENTS.md` sentence about disabling flows and blocking restores before dependent records. With the operation order (`DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, then deletes) this is already satisfied.
- If a sample shows a "downstream before source" order that the sort does not reproduce, stop and investigate before changing the rule.

Assign `step_no` after sorting. Set `system_id` from the observation's logical service, not the replica's name.

Tests: a golden test on all 32 samples (development only), and unit tests for each row of the table above.

Done when: the planner runs end to end on the samples and prints a per-case diff against `sample_output.csv`.

### Phase 10 — Serialization and validation

File: `serialize.py`.

- Write with Python's `csv` module (`csv.writer`, `QUOTE_MINIMAL`, UTF-8, `\n` line endings), columns `case_id,deletion_status,steps_json`, header exactly as given.
- `steps_json = json.dumps(steps, ensure_ascii=False, separators=(",", ":"), sort_keys=True)`. Key order and whitespace are ignored by the grader, but sorted keys make runs byte-identical.
- Empty case: the literal `[]`.
- The validator must fail the run if any of these is false: exactly 518 rows; header exact; one row per request; rows sorted per the decided sort rule; status in the allowed set; `steps_json` parses as a list; `step_no` is 1..N; phases appear in order; each (phase, operation, state) pair is in the allowed table; each step has exactly the 7 fields; evidence ID is empty exactly for remediation and for future verification in INCOMPLETE cases, and refers to a real `file_id`/`activity_id`/`audit_id` otherwise; each cited evidence item's time ≤ the case's `audit_at`; NOT_APPLICABLE ⇒ `[]`; COMPLETE ⇒ only VERIFICATION steps.

### Phase 11 — Evaluation harness

Files: `evaluation/main.py`, `evaluation/metrics.py`, `evaluation/custom_cases.py`.

Run: `python code\evaluation\main.py` (reads `dataset/sample_deletion_requests.csv`, runs the pipeline on it, compares with `dataset/sample_output.csv`).

Metrics (report each in `evaluation_report.md`):
1. **Case-level status accuracy**, plus per-class precision, recall and F1 and the confusion matrix.
2. **Step-level**: treat each step as the tuple (phase, system_id, resource_id, operation, state, evidence_id); report precision, recall, F1 over the multiset of steps per case, averaged over cases. Also report the same without `evidence_id` to separate "wrong resource" from "wrong citation".
3. **Field-level accuracy** over matched steps, per field (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
4. **Sequence accuracy**: exact array equality per case, plus normalized edit distance / longest common subsequence ratio on the ordered tuples.
5. **Sub-task metrics**: resource-linking P/R, remaining-record detection, exposed-PII detection, active-flow detection, restore-risk detection, retention-record detection (derive from the operations in the answers).
6. **Failure triage table**: every mismatching case with the category of error (missed link, wrong state, wrong evidence ID, wrong order, wrong status).

Anti-overfitting:
- Only 32 labeled cases exist. Do leave-one-out thinking: when you fix a failure, ask "what general rule explains this?" and write a unit test for the rule, not for the case.
- Run the full 518 and check **invariants** (no label needed): every cited evidence exists and is ≤ `audit_at`; every step resource was linked by a documented strategy; no COMPLETE case with findings; no INCOMPLETE case without a finding; share of low-confidence links; distribution of statuses printed and sanity-checked against the samples' mix (don't force it).
- At least 3 additional cases created by you (required). Build them as Python objects in `custom_cases.py` (synthetic users, a small in-memory evidence set), and record each case's setup, expected result and outcome in the Markdown report. Suggested cases:
  1. A user whose email changed twice; a stale copy sits under the oldest email in a search index (tests multi-hop alias + hash).
  2. A backup with `restore_allowed: true` plus a disabled flow and an enabled flow (tests restore-risk and flow steps and their ordering).
  3. An account tombstone that still carries an email hash, plus a legal hold that must stay (tests REDACT vs RETAIN).
  4. A non-deletion request containing the word "remove" (tests intent).
  5. Evidence captured *after* `audit_at` that would flip the status (tests the time cutoff).

Done when: the report generator writes real numbers into `evaluation/evaluation_report.md` (not placeholders).

### Phase 12 — Full run, usage tracking, and `output.csv`

1. `llm.py` is the only place that calls a model. Wrap every call so it records: provider, model, input tokens, output tokens (from the API response metadata, not estimates), latency, cache hit/miss, purpose (`intent`, `image`).
2. For the **final** run, clear the cache (`Remove-Item -Recurse -Force .cache`), then run once on all 518 requests so the usage report reflects a true run. If you want cached reruns for development, report cache-hit calls separately.
3. Run:
   ```powershell
   python code\main.py
   ```
   It must write `output.csv` at the repo root.
4. `usage_report.md` must contain: providers and model names; number of model calls (per model and overall); input tokens, output tokens, totals; average tokens per request (divide by 518); estimated total and per-request cost computed from the provider's **current published prices** (cite the price per million tokens you used and the date you checked; do not invent figures). If no model call happened for some stage, state that explicitly.

### Phase 13 — README, packaging, final checks

README (`README.md` at the root of the zip) must cover: purpose, architecture diagram, setup (`python -m venv`, `pip install -r code\requirements.txt`), environment variables (names only), how to run (`python code\main.py`), how to evaluate, how determinism is ensured, where prompts live, known limitations.

Package (PowerShell, from repo root):
```powershell
Get-ChildItem -Recurse -Directory -Filter __pycache__ code | Remove-Item -Recurse -Force
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```
Checks before submission:
- `code.zip` contains no `dataset/`, `.venv`, `node_modules`, caches, `.env`, nested archives, or API keys.
- `code/evaluation/evaluation_report.md` and `code/evaluation/usage_report.md` exist and contain real numbers.
- `output.csv`: header exact, 518 data rows, valid JSON in every row, consecutive `step_no`, sorted.
- `log.txt` at the repo root follows the `AGENTS.md` turn format with real `tool=` and `model=` values.
- A fresh clone + venv + `python code\main.py` reproduces `output.csv` byte-for-byte.
- Grep the repo for emails, user IDs, resource IDs and evidence IDs inside `code/` (excluding tests' synthetic fixtures): there should be none from the real dataset.

---

## 4. Domain reference

### 4.1 `deletion_rules.csv` (as supplied)

| Rule | Category | Condition | Action |
| --- | --- | --- | --- |
| rule_01 | USER_PROFILE | Always | DELETE |
| rule_02 | SECONDARY_IDENTIFIER | Always | DELETE |
| rule_03 | SEARCH_INDEX_ENTRY | Always | DELETE |
| rule_04 | CACHE_ENTRY | Always | DELETE |
| rule_05 | SUPPORT_MESSAGE | Conversation has shared customer/agent/order context that must be retained | REDACT |
| rule_06 | SUPPORT_ATTACHMENT | Attachment belongs only to the deletion subject | DELETE |
| rule_07 | ANALYTICS_PROFILE | Still attributable to a user | ANONYMIZE |
| rule_08 | PRODUCT_TELEMETRY | Still attributable to a user | ANONYMIZE |
| rule_09 | USER_EXPORT | Always | DELETE |
| rule_10 | MARKETING_PROFILE | Always | DELETE |
| rule_11 | EMAIL_DELIVERY_LOG | Log contains a user email address | REDACT |
| rule_12 | SECURITY_AUDIT_LOG | Within the supplied retention period | RETAIN |
| rule_13 | LEGAL_HOLD_RECORD | A supplied legal hold is active | RETAIN |
| rule_14 | BACKUP_ARCHIVE | Restore access can be blocked | RETAIN |
| rule_15 | ACCOUNT_TOMBSTONE | Account deleted; only the stable `user_id` is needed | REDACT |

### 4.2 Resource prefix → system and category

| Prefix | `system_id` | Category | Status |
| --- | --- | --- | --- |
| `account_` | `account_service` | USER_PROFILE | [VERIFIED system] |
| `search_` | `search_service` | SEARCH_INDEX_ENTRY | [VERIFIED system] |
| `support_` | `support_platform` | SUPPORT_MESSAGE or SUPPORT_ATTACHMENT | [VERIFIED system; category per content] |
| `analytics_` | `analytics_platform` | ANALYTICS_PROFILE (or PRODUCT_TELEMETRY) | [VERIFIED system] |
| `audit_record_` | `security_service` | SECURITY_AUDIT_LOG | [VERIFIED system] |
| `backup_` | `backup_service` | BACKUP_ARCHIVE | [VERIFIED system] |
| `data_flow_` | `integration_service` | data flow (not a rule category) | [VERIFIED system] |
| `export_` | `export_service` | USER_EXPORT | [VERIFIED system] |
| `tombstone_` | `identity_service` | ACCOUNT_TOMBSTONE | [VERIFIED system] |
| `cache_` | `cache_service` | CACHE_ENTRY | [HYPOTHESIS: from activity target] |
| `email_delivery_` | `email_delivery_service` | EMAIL_DELIVERY_LOG | [HYPOTHESIS: from activity target] |
| `marketing_` | `marketing_platform` | MARKETING_PROFILE | [HYPOTHESIS] |
| `legal_hold_` | `legal_service` | LEGAL_HOLD_RECORD | [HYPOTHESIS: from RETAIN_RECORD target] |
| `object_` | `object_storage` or `object_store` | SUPPORT_ATTACHMENT? | [HYPOTHESIS: two spellings seen] |

Derive `system_id` from evidence (`origin_system`, `data_store`) and `system_activity.target_system` rather than from this table where they disagree, and report disagreements.

### 4.3 Spec ordering (operation order inside each phase)

- FINDING: `REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`, `REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`
- REMEDIATION: `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`
- VERIFICATION: `VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_PRESENT`, `VERIFY_RECORD_REDACTED`, `VERIFY_RECORD_ANONYMIZED`, `VERIFY_DATA_FLOW_DISABLED`, `VERIFY_RESTORE_BLOCKED`

Each operation has one fixed state (see `problem_statement.md`).

---

## 5. Conservative handling where the spec is silent

Mark each of these as an **assumption** in the README and in the evaluation report, and test it with a custom case.

1. **Ambiguous identity** (email matches two users): do not merge. Prefer the user with corroborating identifiers in the evidence. If still tied, treat as INCOMPLETE only when evidence of exposure exists for one candidate; never delete data for an unconfirmed identity.
2. **Intent unclear** (rules and model disagree): treat as NOT_APPLICABLE, because the spec says no deletion may be authorized without a deletion request. Log the case.
3. **A required retained record is missing** (for example an audit record inside the retention period no longer exists): the allowed operation set has no "restore" step. Report it in the evaluation notes as an unrepresentable violation, and do not invent an operation.
4. **UNKNOWN state** (no snapshot covers a store): do not claim ABSENT. Leave it out of COMPLETE verification and note the gap; consider INCOMPLETE only if other evidence indicates exposure.
5. **SUPPORT_MESSAGE without shared context / SUPPORT_ATTACHMENT shared with another subject**: the rules give no action. Check the PDFs and attachment-catalog events for how ownership is expressed; if still silent, leave the record untouched and note it.
6. **Conflicting evidence**: later snapshot (still ≤ `audit_at`) wins; log the conflict.

---

## 6. Antigravity workflow

How to run this in Antigravity (adapt to the features your version offers):

1. **Open the repo root** (where `AGENTS.md` is) as the workspace. Place this file and `problem_statement.md` there.
2. **Planning first.** Start in the mode that makes the agent produce a plan/task list before editing. Paste the kickoff prompt below. Review and approve the plan before it writes code.
3. **One phase per task.** Give the agent one phase at a time (the phase text from §3 is the task description). Require it to finish with: tests run, the sample evaluation output pasted, and any hypothesis results.
4. **Parallelizable work** (if you use multiple agents): Phase 2 loaders (SQL+JSON / logs / PDF+images+TXT) are independent once `models.py` exists. Phases 3 and 4 are also independent of Phase 2. Phases 5–9 are sequential.
5. **Review gate after every phase.** You (or a second agent acting as reviewer) check: no hardcoding, `audit_at` cutoff respected, tests are meaningful, `log.txt` updated.
6. **Never let it "fix" the score by looking at the answers.** If a sample fails, the fix must be a general rule with its own test.

### 6.1 Kickoff prompt (paste into Antigravity)

```
Read AGENTS.md, problem_statement.md and GHOST_DATA_BUILD_PLAN.md completely before doing anything.
Follow the AGENTS.md logging contract (log.txt) for every turn, with the real tool and model names.
Goal: build the Ghost Data Still Exists deletion-audit agent under code/, writing output.csv at the repo root.
Rules: production code reads only dataset/ files; sample_output.csv is for evaluation only; no hardcoded IDs, emails or case labels;
use only information at or before each case's audit_at; reported statuses are claims; deterministic output.
First produce an implementation plan and a task list that follows Phases 0-13 of GHOST_DATA_BUILD_PLAN.md and wait for my approval.
Do not write solution code until I approve. Treat every [HYPOTHESIS] as unproven until Phase 1 tests it.
```

### 6.2 Per-phase prompt template

```
Work on Phase <N> of GHOST_DATA_BUILD_PLAN.md only.
1. Restate the done criteria.
2. Implement the files listed for the phase, with tests.
3. Run the tests and, if Phase 9 exists, the sample evaluation.
4. Report: what passed, what failed, hypotheses confirmed/rejected, any assumption you made.
5. Do not start the next phase. Update log.txt.
```

### 6.3 Debugging prompt (when a sample case fails)

```
Case <case_id> differs from sample_output.csv.
Print: the identity resolved, the linked resources with link strategy, the state of each, the planned steps, and a diff against the expected steps.
Classify the error: missed link / false link / wrong state / wrong evidence id / wrong order / wrong status.
Propose a GENERAL rule that explains it, state which other sample cases it should also affect, implement it with a unit test,
then re-run the whole sample evaluation and show before/after metrics. Do not special-case this case.
```

---

## 7. Risks and how the plan handles them

| Risk | Mitigation |
| --- | --- |
| Overfitting to 32 samples | General-rule fixes only; invariants on all 518; custom synthetic cases; report precision of low-confidence links. |
| False links (decoys, same names, time-window collisions) | Identifier-based links first; time window only as candidate generation with a second signal; log low-confidence links. |
| Trusting reported success | State comes from evidence only. |
| Using evidence after `audit_at` | Single `as_of(audit_at)` filter at the observation layer, tested. |
| Replica drift missed | Treat primary and every replica as stores; any identified copy counts. |
| LLM hallucinated IDs | LLM never produces IDs or steps; it only returns intent and extracted image fields, which are validated against known formats. |
| Non-deterministic output | Sorted iteration, `temperature=0`, cache, byte-identical rerun check. |
| Windows tooling gaps (poppler, tesseract) | Pure-Python PDF extraction; vision model for PNGs. |
| Judge cannot see JSON/CSV outputs | Put all metrics and cases in the Markdown reports. |

---

## 8. Preparing for the AI Judge interview

Be ready to explain, with evidence from your own reports:
- Why the core is deterministic and where exactly the model is used (intent, PNGs) and why nothing else.
- How an anonymized or absent record is linked to a user, and the limits of the time-window heuristic.
- How `audit_at` is enforced and tested.
- The ordering rule and how it was validated on all 32 samples.
- Why INCOMPLETE answers also verify already-compliant resources.
- How retention (audit logs, legal holds, backups) is preserved instead of deleted.
- What the numbers in `evaluation_report.md` mean, which failures remain, and what you would do for hidden test cases (new aliases, new evidence shapes, other languages).
- The assumptions in §5 and the custom test cases that cover them.
