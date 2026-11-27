# Evaluation Summary

Evaluation evidence is from the official practice kit and independent synthetic tests in this repository. It does not establish performance on hidden organizer data. The official organizer kit is locally available under an ignored evaluation directory and is not included in this documentation bundle.

## Current practice results

Fresh run against the official practice input (200 files, 822 records):

| Measure | Result |
|---|---:|
| PII surfaces visible | 0 / 3,230 (0%) |
| Canaries visible | 0 / 4 |
| Medical probes preserved | 4,855 / 4,855 (100%) |
| Linkage precision / recall / F0.5 | 1.00 / 0.36 / 0.74 |
| Wrong patient merges | 0 observed |
| Files sanitized / quarantined | 193 / 7 |
| Elapsed time / process peak RSS | 5.31 s / 42.6 MB (local run) |

The checker is a practice-only self-check. It does not certify unseen names, formats, or attacks.

## Phase 6 and 6.1 adversarial evidence

The Phase 6.1 comparison found broad-profile singleton counts unchanged: **22/36 (61.11%)** on the original generated dataset before and after, and **36/36 (100%)** on the varied dataset. Targeted generalization experiments did not lower these counts without broader information loss. This unresolved re-identification risk is material; the sample sizes are small, and neither count establishes anonymity or predicts hidden-data performance.

The current independent suite was rerun with fixed seeds 61027 and 93811, plus varied seeds 28697 and 74671. Across those four generated runs it reported zero generated identity surfaces, zero missing clinical probes (11/11 each run), all generated clinician names retained (16/16 each run), exact stay-duration values retained (48/48 each run), no stay-duration generalizations, no raw quarantined copies, no leftover temporary artifacts, no secret in output, and unchanged inputs. In each run, all eight linkage scenarios recorded zero false merges. Broad-profile singleton counts remained 22/36 on fixed runs and 36/36 on varied runs. These synthetic results are not organizer scoring.

The synthetic auxiliary-registry attack showed a fall in unique matches after sanitization for the fixed runs and the additional varied runs, but left some matches possible in some seeds. Generated cohorts contain only 16 profiles and cannot support a robust estimate for real releases. Do not interpret this simulation as an anonymity guarantee.

## Historical phase evidence

- Phase 2.1 and subsequent practice checks reported 0/3,230 known PII surfaces and 0/4 known canaries visible, with 4,855/4,855 medical probes preserved.
- Earlier Phase 3-7 linkage evaluations reported precision 1.00, recall 0.26, F0.5 0.63. After allowing exact same-namespace MRNs to link absent conflicting evidence, the latest practice run reports precision 1.00, recall 0.36, F0.5 0.74, with zero observed false merges. This is a practice-data gain, not proof of hidden-data accuracy.
- Phase 4/4.1 re-identification work corrected a measurement issue. Later phase reports document changes in date-based equivalence groups and the Phase 6.1 singleton limitation above.
- Phase 5/5.1 found the AES-GCM persistence helper is available but unused by the live in-memory pipeline. Fourteen date-shift actions in a prior comparison had no pairable output date because text sanitization subsequently removed those spans; they were not evidence of inconsistent shifts, but remain an accounting/verification limitation.

## Current validation

- Unit tests: 99 passed.
- Compilation: passed (`compileall` over source, tools, tests, and entry point).
- Official output validator: `CONTRACT OK`.
- Official three-run submission checker: `READY TO SUBMIT` for its run checks: exact configured command succeeded, same-secret outputs matched, changed-secret output differed, secret was absent, and input remained unchanged.
- Practice checker: 0/3,230 PII, 0/4 canaries, 4,855/4,855 probes, precision 1.00 / recall 0.36 / F0.5 0.74, no wrong merges or raw copies.
- Independent adversarial suite: four runs completed successfully; 48/48 exact duration values retained per run, zero PII surfaces, and zero false merges across the eight linkage scenarios per run.

The latest checker run found `submission_docs/PROJECT_BRIEF.pdf`, which is a draft. The checker only checks for a recursively located PDF; it does not verify whether that document is the final brief, its page count, content, or team details. The final Project Brief will be created separately in Google Docs by the user. The software checker result therefore does not verify the final brief artifact.

## Limitations and failures

- Phase 6.1 singleton share remains 61.11% on the original generated set and 100% on the varied generated set.
- Linkage recall remains incomplete at 0.36 on the practice fixture; many name-only or conflicting-evidence pairs are intentionally unresolved.
- FHIR Bundle processing is not full R4 schema/reference validation.
- There is no universal output PII scanner for arbitrary new schemas or opaque attachments.
- At-rest encryption is not used for current in-memory intermediates; Python memory/swap and secure erasure are outside the guarantees.
- Local CPU/RSS measurements do not establish the organizer's whole-process-tree maximum resource behavior on hidden input.
- The exact-stay default protects clinical fidelity but leaves stay duration available as a quasi-identifier; the tested singleton rates did not improve or worsen on the four small generated cohorts.
- The final Google Docs Project Brief has not been provided for review; its content and team details remain unverified.
