# Phase 2 Evaluation

Evaluation date: 2026-11-26. This report records the current implementation's results on the official practice data and synthetic unit cases. The organizer's `check_dev.py` describes itself as a rough guide, not the hidden-data score.

## Implementation scope

The detector is split into normalization, medical-span protection, and PII rules in `src/detection/`. It normalizes Unicode and Hindi digits for matching, derives Devanagari/Latin name keys, classifies structured fields, and produces internal spans with category, method, and confidence. It handles English, Devanagari, and Hinglish labels; patient and relative names; phone, Aadhaar-like, ABHA, PAN, email, MRN/UHID, PIN, address components, and insurance identifiers. The pipeline harvests candidate names from input context, processes structured CSV/TSV/JSON and FHIR-like resources with field context, sanitizes matching filenames/keys, and decodes encoded text for sanitization. Clinical patterns and medical fields protect diagnoses, doctors, drugs, values, units, frequencies, and durations.

No practice identities or expected outputs were added as production rules. The synthetic tests use generated examples, spelling changes, punctuation variations, transliteration, identifier variants, and ambiguous clinical contexts.

## Measured results

Commands run from `doctor/`:

```text
python3 -m unittest discover -s tests -v
RAKSHA_SECRET=phase2-eval-2026 python3 main.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase2-final
python3 .local-evaluation/official-kit/validate_output.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase2-final
python3 .local-evaluation/official-kit/check_dev.py --output /private/tmp/raksha-phase2-final
python3 .local-evaluation/official-kit/check_submission.py --repo . --run
```

| Measure | Phase 1 baseline | Phase 2 current | Change |
|---|---:|---:|---:|
| PII pieces visible | 3,220/3,230 (99.7%) | 195/3,230 (6.0%) | -93.7 percentage points |
| Planted canaries found in output | 4/4 | 3/4 | 1 fewer |
| Medical probes retained | 4,855/4,855 (100%) | 4,840/4,855 (99.7%) | -0.3 percentage points |
| Output contract | `CONTRACT OK` | `CONTRACT OK` | pass |
| Unit tests | 7 | 24/24 pass | +17 cases |
| Raw unsupported/broken files copied unchanged | 0 | 0 | no regression |

The Phase 1 baseline figures above are the team's Phase 1 output, recorded in the workspace audit. The untouched organizer starter had different baseline metrics (2,718/3,230 leaks, 4/4 canaries, and all 4,855 clinical probes retained); it is not the comparator in this table.

The latest run processed 200 files: 193 sanitized and 7 quarantined, with 822 records. The practice checker reports no phone, Aadhaar, masked Aadhaar, DOB, email, PAN, or ABHA leaks. Leakage by remaining category is:

| Category | Visible / total |
|---|---:|
| Patient name | 68/962 (7.1%) |
| MRN / UHID | 49/850 (5.8%) |
| Locality | 20/103 (19.4%) |
| Relative name | 18/232 (7.8%) |
| Landmark | 13/64 (20.3%) |
| House | 12/136 (8.8%) |
| Insurance ID | 8/22 (36.4%) |
| Village | 6/150 (4.0%) |
| PIN | 1/136 (0.7%) |

By script, reported leakage is Latin 4.8%, Devanagari 18.9%, and Hinglish 23.4%. By channel it is content 5.4%, filename 8.3%, base64 0%, metadata 50%, key 0%, and header 25%. These are official checker ratios across each script/channel's own denominator; they should not be compared as absolute counts.

## Residual-case audit

An aggregate audit of every still-visible truth entity (without printing the synthetic values) found these clusters:

- **Patient names:** 68 remain. Most are in TXT free text (33: 26 Devanagari, 4 Hinglish, 3 Latin), with 33 in JSON (22 Latin, 10 Hinglish, 1 Devanagari), plus 2 CSV headers. This points to sparse identity context and cross-script spelling coverage rather than a failure of labeled name fields.
- **Record identifiers:** 49 MRN/UHID-like values remain. They are concentrated in JSON content (19), JSON metadata (20), and TXT content (6), with 4 in TXT filenames. Identifier conventions and metadata locations are not covered consistently by the current field and pattern rules.
- **Address components:** locality, landmark, house, village, and PIN leaks cluster in JSON and CSV. The current general address parser does not reliably identify unlabeled nested address components or all column naming conventions.
- **Insurance IDs:** all 8 visible examples are CSV content. The production column/value classifier misses some insurer-specific formats.
- **Relative names:** 12 of 18 leaks are Hinglish TXT and 6 are Latin JSON. Relationship labels and spelling/connective variants need broader context handling.
- **Canaries:** the checker found three of four unique canaries. The missed canary is a JSON content occurrence; the TXT content, CSV content, and JSON base64 occurrences were found. This shows a miss in one structured JSON path, despite base64 decoding working for the other planted case.
- **Medical retention losses:** all 15 missing probes are from TXT. Running those probe strings through the current detector shows 13 overlaps with `PATIENT_NAME` from `input_name_lexicon`, one with `RELATIVE_NAME` from that lexicon, and one with a different/no classified overlap. This is a real over-redaction risk: the input-derived name set can override a valid clinical phrase in free text. The count is small, but the probes are not all proven to be false positives without case-level manual review.

The synthetic adversarial suite verifies key local contexts including `C/O fever` versus a relative name, doctor names, medicine/dose strings, clinical lab values, Hindi and Romanized relationship labels, and punctuation/transliteration changes. Passing these tests does not cover the remaining practice clusters above.

## Other checks and limitations

- `python3 -m unittest discover -s tests -v`: 24 tests passed.
- `python3 -m compileall -q src main.py`: passed.
- Organizer validator: `CONTRACT OK`.
- Submission checker: `READY TO SUBMIT`, with warnings for the missing two-page Project Brief PDF and identical output under different secrets. The second warning is expected before keyed pseudonyms/date shifting are implemented; it confirms those later-phase requirements remain unmet.
- Linking remains intentionally absent: practice linkage precision/recall/F0.5 are all 0.00 because Phase 3 is not implemented.
- The detector is deterministic and rule-based; its input-derived candidate list and small generic name-variant rules are not a comprehensive Indian name model. Unseen transliterations, unlabeled metadata, hospital-specific IDs, and free-text context remain weaknesses.
- The current checker results do not establish hidden-data performance, full FHIR R4 validity, protection from quasi-identifier attacks, or submission readiness for the complete PRD.

Phase 2 has an evaluation record, but its measured misses remain material. Phase 3 has not been started.
