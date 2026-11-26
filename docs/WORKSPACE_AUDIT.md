# Workspace Audit

Audit date: 2026-11-26

## Workspace and project roots

The VS Code workspace root is `/Users/vyom/Downloads/Raksha`.

- `doctor/` is the team's working repository. At audit time it contains the complete project PRD (`prd.md`) and no implementation. It has no prior commits.
- `Secret-Wards-ToolKit/` is the official organizer kit, on its own Git branch. It contains the practice data, answer key, attacker files, starter, documentation, and organizer tools. Its working tree was clean during inspection.
- No `Hackathon_Project/`, `TEAMMATE2_INTEGRATION.md`, or `AGENTS.md` was present in the workspace. No symbolic links were found.

The practice answer key and attacker data are evaluation resources. They must not be used as hardcoded production rules or copied into the submission application.

## Official material inspected

Read the organizer README, `START_HERE.md`, all challenge documents in `docs/`, starter README and code, `raksha.toml`, policy, requirements, scoring configuration, brief template, practice checker, output validator, and submission checker. The submission contract in `docs/SPEC.md` is authoritative where the PRD's illustrative schema differs from it.

Key contract details:

- Runtime command receives `--input` and `--output`; runtime is offline and CPU-only.
- Output includes `sanitized/`, `report.json`, and `records.jsonl`.
- Every input file must be represented in report `files` by its SHA-256 and status (`sanitized`, `quarantined`, or `suppressed`).
- Sanitized files use UTF-8 and preserve supported formats; unsafe or unsupported data must not be copied as a sanitized file.
- Record locations are CSV/TSV `row:N`, JSON Pointer, or `doc`. The reported pseudonym must also appear in the sanitized record to earn linkage credit.
- The validator checks structure, accounting, UTF-8 and record references. The practice checker measures PII leakage, clinical preservation, canaries, linkage, and raw copies. The submission checker additionally checks repeatability, secret-dependent output, input integrity, and repo setup.

## Existing starter and measured baseline

The organizer starter is standard-library-only. It recursively visits files in sorted order; decodes UTF-8, UTF-8 BOM, UTF-16, and cp1252; processes CSV/TSV, JSON, and text; quarantines unsupported, empty, or malformed files in its report; emits a SHA-256-based report and records JSONL; and includes HMAC pseudonym, date-shift, and age-band helpers.

Known gaps in the starter include narrow regex-only detection, no cross-record linking, no pseudonym insertion into sanitized content, no filename/header cleanup, no quasi-identifier transformations, and no FHIR validation. Its traversal follows ordinary `Path.is_file()` semantics without explicit symlink, path, size, or nesting controls. Quarantined bytes are not persisted, which avoids copying raw data into the release.

Commands run from `Secret-Wards-ToolKit/`:

| Command | Actual result |
|---|---|
| `RAKSHA_SECRET=practice python3 starter/main.py --input dev/input --output /private/tmp/raksha-baseline-phase0` | Exit 0; 200 files accounted for: 195 sanitized, 5 quarantined; 823 records emitted. |
| `python3 validate_output.py --input dev/input --output /private/tmp/raksha-baseline-phase0` | `CONTRACT OK`. |
| `python3 check_dev.py --output /private/tmp/raksha-baseline-phase0` | 2,718/3,230 PII entities leaked (84.1%); 4/4 canaries found; 4,855/4,855 medical probes preserved; linkage F0.5 0.00; 0 raw copies. |
| `python3 check_submission.py --repo starter --run` | Failed as shipped: placeholder team name and `python` command exits 127 in this environment; consequent output validation fails. README length and missing brief PDF are warnings. Input was left unchanged and the generated secret was not found in output/logs. |

The submission checker was run against the unmodified official starter. Its failure is not evidence about a future team implementation; it records the initial state and a concrete portability issue to avoid.

## Phase 1 implementation status

The team implementation now lives in `doctor/`. It has a standard-library CLI, separate policy loading, bounded file ingestion, UTF-8 output, CSV/TSV and JSON/text handling, record locators, JSON/FHIR-Bundle document locators, per-file quarantine status, contract-shaped reports, and deterministic records JSONL. The current format and report helpers remain grouped in the pipeline module and can be split as later features need clearer boundaries. It refuses a missing secret, non-empty output directories, and output paths inside the input tree. It does not yet use the secret for output transformations. Its structural FHIR checks are limited and do not constitute full R4 validation.

After implementation, `python3 -m unittest discover -s tests -v` passed 7 tests; the organizer validator printed `CONTRACT OK`; and the submission checker printed `READY TO SUBMIT` with two warnings (missing Project Brief PDF and identical output under different secrets). The practice checker reports 99.7% PII leakage and 4/4 canaries, with all 4,855 clinical probes retained. Those results confirm the format baseline but also show that this is not a privacy-safe release. The official submission checker does not measure privacy performance.

## Phase 2 follow-up

Phase 2 has since added multilingual detection, medical-span protection, and 17 further tests. The measured current result and residual leak/clinical-loss audit are recorded in [`PHASE2_EVALUATION.md`](PHASE2_EVALUATION.md); do not use the earlier Phase 1 measurements in this audit as current privacy metrics.

## Architecture decision

Use `doctor/` as the submission root because it holds the project PRD and is the team's workspace repository. Keep the official kit read-only and use it for contract validation and practice scoring. Build the implementation in `doctor/` rather than editing organizer files. Configuration is isolated; the Phase 1 pipeline currently combines file handling and reporting. Detection, linkage, privacy transformations, and hardening remain subsequent phases.

## Risks and constraints

- Phase 1's format-valid baseline does not remove all PII; it must not be described as privacy-ready.
- Blindly preserving input filenames, keys, and values can expose PII until later detection/security phases.
- FHIR must either be validated after transformation or quarantined when processing cannot be trusted.
- The official validator only checks the output contract; it does not prove privacy or clinical safety.
- The starter submission check assumes `python` exists. Use a portable `python3` command in this workspace.
- The starter's practice metrics are not a hidden-data performance estimate.

