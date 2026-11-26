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

