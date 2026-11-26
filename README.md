# Secret Wards

This repository is the team's implementation for the Secret Wards privacy firewall challenge. It runs offline with Python 3 and the `cryptography` package for AES-GCM. Phase 2.1 adds residual leakage fixes and contextual medical-integrity safeguards to multilingual detection. Phase 5 adds domain-separated keys, authenticated-encryption support for sensitive persisted intermediates, privacy-safe structured logs, bounded no-follow input reads, and private output writes. Practice metrics and limitations are recorded in the local, git-ignored `docs/` folder; they are not hidden-data guarantees.

## Run

Set a secret through the environment, then invoke the CLI:

```bash
RAKSHA_SECRET=local-practice python3 main.py --input PATH/TO/input --output PATH/TO/output
```

The output directory must be new or empty and must be outside the input directory. The program creates `sanitized/`, `report.json`, and `records.jsonl`. Supported files are CSV, TSV, JSON, and plain text. Unsupported, malformed, empty, oversized, too-deep, or symlink inputs are reported as quarantined and are not copied to the sanitized release. The input tree is read-only from the program's perspective.

## Configuration and dependencies

Safety limits are in `config/policy.yaml`. Install the maintained AES-GCM dependency with `python3 -m pip install -r requirements.txt`; runtime processing is offline. `raksha.toml` contains the organizer run command and uses `python3` for portability in this workspace.

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

Phase 1 provides recursive discovery, encoding handling, CSV/TSV/JSON/text serialization, JSON record locators, conservative quarantine, report generation, and records JSONL. Phase 2 adds multilingual explainable detection and medical-value protection. Phase 3 adds conservative patient linkage and keyed pseudonyms; Phase 4 adds consistent date shifting, age/location generalization, and equivalence-class risk measures; Phase 5 adds key separation, an AES-GCM envelope for any required sensitive persistence, privacy-safe logs, bounded no-follow reads, and private atomic output writes. Full FHIR R4 validation and a universal automatic output PII scanner remain limitations. Practice checks do not establish hidden-data performance.

See `prd.md`, `docs/WORKSPACE_AUDIT.md`, and `docs/IMPLEMENTATION_PLAN.md` for requirements and current findings.
