# Implementation Plan

This plan follows `prd.md` and the organizer's `Secret-Wards-ToolKit/docs/SPEC.md`. The organizer specification is authoritative for output fields and validator expectations.

## Phase 0 — Workspace audit (complete)

- Locate and read the full PRD, organizer docs, starter, validators, and checkers.
- Run the starter, contract validator, practice checker, and submission checker.
- Record actual outcomes in `WORKSPACE_AUDIT.md`.

## Phase 1 — Runnable baseline (complete)

1. Establish `doctor/` as the submission root with `main.py`, `raksha.toml`, `requirements.txt`, and policy configuration.
2. Add small modules for safe discovery/decoding, CSV/TSV/JSON/text parsing, JSON record locations, output serialization, and reporting.
3. Require `RAKSHA_SECRET`; never print or persist it.
4. Guard against symlinks, output nested under input, excessive file sizes/depth, malformed data, and unsupported formats. Account for every discovered input in the report; quarantine by status without copying raw bytes.
5. Add focused automated tests for supported formats, locators, malformed inputs, quarantine accounting, and path safety.
6. Run the local tests, organizer validator, practice checker, and submission checker. The Phase 1 target is a reliable contract-valid baseline, not a claim of PII safety.

Phase 1 results (2026-11-26): 7 unit tests pass; the organizer validator prints `CONTRACT OK`; `check_submission.py --repo ../doctor --run` prints `READY TO SUBMIT` with warnings for the missing final brief PDF and secret-independent output. The practice self-check still finds 99.7% of listed PII and all 4 canaries, while preserving all 4,855 medical probes. This is an intentionally incomplete baseline; proceed to Phase 2 detection and clinical protection next.

## Phase 2 — Multilingual PII detection (implemented and evaluated)

- Add Unicode/script and Hindi numeral normalization without mutating retained clinical values.
- Add structured-field and contextual detection for direct identifiers, names, relatives, addresses, and hidden channels.
- Protect medical terms and dosages; resolve overlaps conservatively.
- Measure detection and preservation with practice checks and synthetic adversarial tests.

Phase 2 evaluation (2026-11-26): 24 standard-library unit tests pass. The practice checker reports 195/3,230 PII pieces visible (6.0%), 3/4 canaries found, and 4,840/4,855 medical probes retained (99.7%). The validator prints `CONTRACT OK`; the submission checker prints `READY TO SUBMIT` with warnings for the missing Project Brief PDF and output unchanged across secrets (expected before Phase 3 pseudonyms/date shifts). Full breakdown and residual-case audit: [`PHASE2_EVALUATION.md`](PHASE2_EVALUATION.md). Phase 2 is documented; do not start Phase 3 until the project owner reviews these residual risks and directs the next phase.

Phase 2.1 evaluation (2026-11-26): 36 unit tests pass; compileall passes; the validator prints `CONTRACT OK`; the official practice checker reports 0/3,230 visible PII pieces, 0/4 planted canary surfaces visible, and 4,855/4,855 medical probes preserved. The submission checker prints `READY TO SUBMIT` with a warning that output is independent of `RAKSHA_SECRET`; patient linkage and pseudonymization remain out of scope. Residual-case review and full metrics: [`PHASE2_1_EVALUATION.md`](PHASE2_1_EVALUATION.md). Phase 2.1 is evaluated; do not start Phase 3 without a separate instruction.

## Phase 3 — Patient linkage

- Extract normalized identity features and generate candidates with blocking.
- Score strong identifiers, names, cross-script variants, supportive clues, and contradictions.
- Use conservative cluster checks; leave uncertain records unlinked.
- Add HMAC pseudonyms in both output records and `records.jsonl`; measure pairwise precision/recall.

## Phase 4 — Privacy transformations

- Apply deterministic secret-keyed date shifts, truthful age bands, and configurable location generalization.
- Analyze rare quasi-identifier combinations and simulate attacker matching.
- Generalize or suppress risky combinations only where medical utility can be retained.

## Phase 5 — Security hardening

- Sanitize filenames and hidden metadata/keys/headers; add output leakage scanning.
- Keep logs and errors free of record content and secrets.
- Avoid persisting raw intermediates; encrypt any sensitive persisted intermediate if one becomes necessary.
- Harden quarantine and temporary-file cleanup.

## Phase 6 — Adversarial testing and optimization

- Add multilingual, same-name, shared-family-contact, contradiction, medical-preservation, malformed-file, and quasi-identifier attack cases.
- Run the organizer self-check and submission checker, track measured deltas, and fix regressions.
- Measure runtime and peak memory; optimize candidate blocking and large-file handling.

## Phase 7 — Submission readiness

- Finish README, policy, requirements, architecture/evaluation docs, and the two-page Project Brief PDF.
- Run final checks from the submission root with the exact configured command.
- Claim readiness only if the organizer tools actually print `CONTRACT OK` and `READY TO SUBMIT`.

