# Phase 3 Evaluation — Patient Linkage and HMAC Pseudonyms

Evaluation date: 2026-11-26. Results are from the copied official practice set. The organizer labels `check_dev.py` a rough guide; these figures do not predict hidden-data performance.

## Implementation

- Added `src/linkage/` with dataset-wide CSV/TSV, JSON, FHIR Bundle, and text identity extraction, scoped identifier normalization, deterministic candidate blocking, explainable pair decisions, conservative cluster checks, and HMAC-SHA256 pseudonyms.
- HMAC uses a versioned domain separator and returns a 128-bit Base32 token. Secrets shorter than 16 UTF-8 bytes are rejected. No raw evidence, anchors, decision explanations, or secret are serialized.
- The pipeline extracts and resolves records before sanitization, then overlays a pseudonym only at a patient-scoped carrier. It emits the same pseudonym in `records.jsonl` and the corresponding sanitized record. Clinical fields remain handled by the existing Phase 2 medical-preservation layer.
- MRNs are namespaced by source hospital and prefix. Text linkage ignores generic name-lexicon hits, and identifier labels require an MRN numeric core. Conflicting or non-unique name/relative evidence remains unresolved.
- Added synthetic tests for HMAC stability/rotation, cross-site shared IDs, Devanagari transliteration, homonyms, conflicting DOB/MRN/phone evidence, family phone sharing, nested JSON, FHIR Patient identity replacement, locator consistency, and clinical-value preservation. No practice patients or canaries are embedded in production logic.

## Measured results

The Phase 2.1 output is the immediate pre-Phase-3 baseline. Phase 1 and Phase 2 history is included for context.

| Measure | Phase 1 baseline | Phase 2.1 before Phase 3 | Phase 3 final |
|---|---:|---:|---:|
| Visible PII | 3,220/3,230 (99.7%) | 0/3,230 (0%) | **0/3,230 (0%)** |
| Canary surfaces found in output | 4/4 | 0/4 | **0/4** |
| Medical preservation probes retained | 4,855/4,855 (100%) | 4,855/4,855 (100%) | **4,855/4,855 (100%)** |
| Pairwise linkage precision | 0.00 | 0.00 | **1.00** |
| Pairwise linkage recall | 0.00 | 0.00 | **0.26** |
| Pairwise F0.5 | 0.00 | 0.00 | **0.63** |
| Wrongly merged pseudonym clusters | 0 | 0 | **0** |
| Output contract | `CONTRACT OK` | `CONTRACT OK` | **`CONTRACT OK`** |

The phase 1 figures are the team baseline recorded in `docs/WORKSPACE_AUDIT.md`; the untouched organizer starter had a different baseline. Phase 3 processed 200 files (193 sanitized, 7 quarantined) and emitted 822 locators. Of those, 619 records carried pseudonyms across 188 unique pseudonyms; the remaining 203 had `patient: null`. An independent output scan found all 619 pseudonyms in their corresponding exported files.

`check_dev.py` calculates pairwise metrics over required-link records and excludes ambiguous records from recall. Its baseline had no pseudonyms, so precision/recall/F0.5 were all 0.00. After Phase 3, it reported precision 1.00, recall 0.26, F0.5 0.63, and no wrong merges. It does not report per-pair missed-link details; the remaining missed links are represented in the 0.26 recall and unresolved records rather than attributed to a fabricated category.

## Checks run

Commands run from `doctor/`:

```text
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -v
RAKSHA_SECRET='phase3 evaluation secret 2026' python3 main.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase3-out
python3 .local-evaluation/official-kit/validate_output.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase3-out
python3 .local-evaluation/official-kit/check_dev.py --output /private/tmp/raksha-phase3-out
python3 .local-evaluation/official-kit/check_submission.py --repo . --run
```

Compilation passed. The expanded unit suite contains **49 tests, all passing**. The validator returned `CONTRACT OK`. The practice privacy checker returned zero visible PII, 0/4 canary surfaces found, 4,855/4,855 medical probes retained, and zero wrong merges. The submission checker returned `READY TO SUBMIT`, confirmed identical outputs for repeated use of one secret, changed output for a rotated secret, no secret in outputs/logs, and an unchanged input folder. The organizer kit was not modified.

## Residual weaknesses and limitations

- Linkage recall remains low at 0.26. The resolver deliberately leaves ambiguous and weakly evidenced records unlinked; name-only records, incomplete identity fields, and conflicting household evidence are the main expected sources of missed links. The practice checker does not expose an auditable per-miss classification, so this report does not invent one.
- Names rely on normalized forms, a small transliteration aid, and Latin Soundex candidate blocking. Unseen spellings and less common transliterations may be missed; phonetic similarity is never sufficient by itself to accept a link.
- Text MRN extraction requires at least three digits to reject label-adjacent words. This can miss a legitimate unusually short or alphabetic record number.
- MRN namespace inference uses source path and identifier prefix. A dataset with inconsistent hospital naming or reused prefixes may still create false conflicts or ambiguous records.
- Household phone reuse, relative-name reuse, stale demographics, and collisions in weak identifiers remain inherently ambiguous. The resolver favors null over unsupported merges.
- FHIR linking treats a Bundle as a document locator and chooses a Patient-scoped carrier; bundles containing multiple unrelated Patient resources cannot be independently pseudonymized per patient under the current one-document record contract.
- The practice checker is synthetic and small relative to real hospital data. Passing it is not a guarantee of hidden-data accuracy, privacy, or clinical safety.

## Completion status

Final post-documentation compilation, all 49 unit tests, practice pipeline run, output validator, full practice privacy/linkage checker, and three-run official submission checker were rerun successfully. Phase 3 is documented and ready for review. No Phase 4 work was started.
