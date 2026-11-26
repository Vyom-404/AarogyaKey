# Phase 2.1 Evaluation — Residual Leakage and Clinical Integrity

Evaluation date: 2026-11-26. This report covers the current workspace implementation against the copied official practice set. The organizer describes `check_dev.py` as a rough guide; these metrics are not a hidden-data score or a privacy guarantee. Phase 3 patient linkage and pseudonymization were not started.

## Changes evaluated

- Extended contextual detection for Hindi `आयु` / `उम्र` labels, patient names before relationship markers, Hinglish kinship suffixes, name references attached to clinical notes, and patient names preceding known-history text.
- Scoped one-token patient references to explicit record or person context. Known-name matches no longer trigger merely because a name appears somewhere in text; clinical terms such as ASHA remain intact when they are not person references.
- Added same-record patient-name matching for possessive and kinship references in JSON notes.
- Redacted identifier-shaped values inside FHIR medical resources while preserving diagnosis and clinical display fields. Preserved concrete metadata keys during recursion so `source_path` and similar identifier-bearing fields receive their intended detection rules.
- Added conservative detection for compact MRN forms and names attached to MRN-bearing CSV headers.
- Added a registration-only village-form check for demographic `City` values. Generic `City` columns remain unchanged. The check uses contextual field/path information and name morphology, not practice patient or canary values.
- Fixed JSON component-name traversal for local and split name values, and added focused tests for nested metadata, identifier values, and address context.

No practice canary, patient name, or expected output is embedded as a production rule. The rules use labels, record-local links, field context, relationship grammar, and identifier shapes.

## Measured comparison

`check_dev.py` counts visible truth surfaces as leakage. Its canary line reports canary surfaces found in output, so **0/4 found means all four practice canary surfaces were absent from output**.

| Measure | Phase 1 baseline | Phase 2 report snapshot | Immediately before Phase 2.1 | Phase 2.1 final |
|---|---:|---:|---:|---:|
| Visible PII | 3,220/3,230 (99.7%) | 195/3,230 (6.0%) | 119/3,230 (3.7%) | **0/3,230 (0.0%)** |
| Canary surfaces visible | 4/4 | 3/4 | 0/4 | **0/4** |
| Medical probes retained | 4,855/4,855 (100%) | 4,840/4,855 (99.7%) | 4,855/4,855 (100%) | **4,855/4,855 (100%)** |
| Raw unsupported/broken files copied unchanged | 0 | 0 | 0 | **0** |
| Output contract | `CONTRACT OK` | `CONTRACT OK` | `CONTRACT OK` | **`CONTRACT OK`** |

The Phase 1 and Phase 2 report snapshot figures are historical measurements copied from `docs/WORKSPACE_AUDIT.md` and `docs/PHASE2_EVALUATION.md`. The immediate pre-2.1 figures (119/3,230, 0/4 visible canaries, 4,855/4,855 medical probes) were remeasured on the last Phase 2 implementation before these edits. Phase 2.1 was run from scratch on the same copied practice input. It processed 200 files: 193 sanitized, 7 quarantined, 822 records.

Final practice categories were all zero: patient names, relative names, MRN, village, locality, house, PIN, landmark, phone, email, DOB, Aadhaar, masked Aadhaar, ABHA, PAN, and insurance IDs. Leakage was zero in content, filename, encoded content, metadata, keys, and headers. The checker found no practice PII surface or canary still visible.

## Medical integrity and failed probes

The final checker retained all 4,855/4,855 medical preservation probes. The final output preserves the practice diagnoses, procedures, medicines, doses, frequencies, durations, units, vitals, and lab values checked by the organizer.

During iteration, a broad city-field experiment removed 83 preservation probes; it was narrowed to demographic city values with village-like morphology and evaluated again. A later contextual-name change removed two `ASHA` clinical references. Inspection found a substring cue treating “patients” as the identity word “patient.” The cue now requires a word boundary; both references survive and the final medical score returned to 100%. The final run has **zero failed medical probes and zero checker-reported clinical false positives**. These two interim regressions are documented here rather than hidden.

## Residual leaks and false positives

- **Remaining practice leaks:** none detected by the official practice checker (0/3,230). No PII category or hiding channel had a visible practice surface.
- **Remaining practice canaries:** none visible (0/4 found in output).
- **Remaining practice medical false positives:** none reported (4,855/4,855 preserved).
- **Known limitations outside this practice set:** an unfamiliar identifier format without a label or known structured field may be missed; names with unseen transliterations or unusual tokenization may not match; city/village morphology is language- and region-dependent; and a name that is also a clinical term can still be ambiguous without reliable context. These are residual model limitations, not observed failures in the final checker run.
- **Scope not covered:** records are not linked or pseudonymized. The checker consequently reports linkage precision, recall, and F0.5 as 0.00. That is expected at this phase and is not counted as a Phase 2.1 PII leak result.

## Regression tests and checks

The test suite now contains 36 tests. New cases cover contextual Hindi age labels, patient names before S/o/D/o/W/o, C/o ambiguity, Hinglish kinship forms and note references, clinical-name negatives, compact and nested MRNs, FHIR encounter identifiers, metadata paths, nested address fields, demographic village-like city values, and identifier-bearing headers. Both positive and negative examples are included; the tests use synthetic identities.

Commands run from `doctor/`:

```text
python3 -m unittest discover -s tests -q                 # 36 passed
python3 -m compileall -q src main.py                     # passed
RAKSHA_SECRET=phase2-1-local python3 main.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase2-1-final5
python3 .local-evaluation/official-kit/validate_output.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase2-1-final5  # CONTRACT OK
python3 .local-evaluation/official-kit/check_dev.py --output /private/tmp/raksha-phase2-1-final5  # 0 leaks; 0/4 canary surfaces; 4,855/4,855 preserved
python3 .local-evaluation/official-kit/check_submission.py --repo . --run
```

The submission checker prints `READY TO SUBMIT` with one warning: output is identical under different `RAKSHA_SECRET` values. Keyed pseudonyms and date shifts are outside this phase. It also counts the practice fixture's scanned discharge PDF as the Project Brief PDF; that is a fixture false positive and does not verify a real two-page brief.

## Changed files

- `src/detection/detector.py` — contextual rules, identifier shapes, scoped name matching, and explainable detection spans.
- `src/detection/medical.py` — protected clinical terminology used by the contextual detector.
- `src/pipeline.py` — nested JSON, FHIR identifier, metadata, patient-name and demographic locality context.
- `tests/test_detection.py` and `tests/test_pipeline.py` — synthetic regression coverage.
- `docs/PHASE2_1_EVALUATION.md` — this measured evaluation.
- `docs/IMPLEMENTATION_PLAN.md` and `README.md` — current phase status and evaluation links.

The organizer kit under `.local-evaluation/official-kit/` was not modified. A zero practice leakage result does not prove performance on hidden, real, or adversarially different records.
