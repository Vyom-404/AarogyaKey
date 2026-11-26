# Secret Wards

This repository is the team's implementation for the Secret Wards privacy firewall challenge. It runs offline with Python 3 and the standard library. Phase 2.1 adds residual leakage fixes and contextual medical-integrity safeguards to multilingual detection. The official practice run measured 0/3,230 visible PII pieces and 4,855/4,855 medical probes preserved; this is not a hidden-data guarantee. See [`docs/PHASE2_1_EVALUATION.md`](docs/PHASE2_1_EVALUATION.md) for the full comparison, failed-case history, limitations, and checks.

## Run

Set a secret through the environment, then invoke the CLI:

```bash
RAKSHA_SECRET=local-practice python3 main.py --input PATH/TO/input --output PATH/TO/output
```

The output directory must be new or empty and must be outside the input directory. The program creates `sanitized/`, `report.json`, and `records.jsonl`. Supported files are CSV, TSV, JSON, and plain text. Unsupported, malformed, empty, oversized, too-deep, or symlink inputs are reported as quarantined and are not copied to the sanitized release. The input tree is read-only from the program's perspective.

## Configuration and dependencies

Safety limits are in `config/policy.yaml`. The current implementation uses only the Python standard library; `requirements.txt` is intentionally empty. `raksha.toml` contains the organizer run command and uses `python3` for portability in this workspace.

## Checks

Run the local unit tests:

```bash
python3 -m unittest discover -s tests -v
```

The local organizer kit is stored in `.local-evaluation/official-kit/`. It is git-ignored because it contains the practice answer key; do not add it to a submission commit. Run the application and organizer checks from this directory:

```bash
RAKSHA_SECRET=local-practice python3 main.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-check
python3 .local-evaluation/official-kit/validate_output.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-check
python3 .local-evaluation/official-kit/check_dev.py --output /private/tmp/raksha-check
python3 .local-evaluation/official-kit/check_submission.py --repo . --run
```

The contract validator checks format and accounting, not privacy. The practice checker uses the practice answer key and measures leakage, clinical retention, canaries, and linkage. Do not treat a contract-valid output as a privacy-safe output.

The copied practice input contains a scanned PDF, so `check_submission.py` may incorrectly count that fixture as the required Project Brief PDF. That result does not verify the brief; inspect the reported path before treating the PDF check as passed. The `.local-evaluation/` directory is excluded from Git and will not be present in clones.

## Current scope and next work

Phase 1 provides recursive discovery, encoding handling, CSV/TSV/JSON/text serialization, JSON record locators, conservative quarantine, report generation, and records JSONL. Phase 2 adds Unicode/Hindi digit normalization, Devanagari transliteration keys, explainable confidence-scored detection, relationship and structured-field rules, medical-value protection, and synthetic adversarial tests. Phase 2.1 has an updated practice evaluation in [`docs/PHASE2_1_EVALUATION.md`](docs/PHASE2_1_EVALUATION.md). Patient linkage, HMAC IDs, date and age transformations, location generalization, full FHIR validation, output leakage scanning, and quasi-identifier attack measurement remain unimplemented. The practice result does not establish hidden-data performance.

See `prd.md`, `docs/WORKSPACE_AUDIT.md`, and `docs/IMPLEMENTATION_PLAN.md` for requirements and current findings.
