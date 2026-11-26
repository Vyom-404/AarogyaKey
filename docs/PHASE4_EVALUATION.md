# Phase 4 Evaluation — Advanced Privacy Protection and Re-identification Risk

Evaluation date: 2026-11-26. The figures below are from the copied official practice dataset. `check_dev.py` is an organizer-provided rough practice check, not a prediction of hidden-set or real-world performance.

## Outcome

Phase 4 adds locator-aware quasi-identifier transformations, HMAC-keyed patient date shifts, truthful age bands, location and PIN generalization, stay-duration buckets for low-k profiles, and aggregate equivalence-class measurements. The pipeline still processes the same 200 input files (193 sanitized, 7 quarantined) and emits 822 record locators.

| Measure | Phase 3 baseline | Phase 4 result |
|---|---:|---:|
| Visible PII surfaces | 0/3,230 | **0/3,230** |
| Canary surfaces visible | 0/4 | **0/4** |
| Medical probes preserved | 4,855/4,855 | **4,855/4,855** |
| Linkage precision | 1.00 | **1.00** |
| Linkage recall | 0.26 | **0.26** |
| Linkage F0.5 | 0.63 | **0.63** |
| Wrong patient merges | 0 | **0** |
| Output contract | `CONTRACT OK` | **`CONTRACT OK`** |
| Submission checker | `READY TO SUBMIT` | **`READY TO SUBMIT`** |

The final official privacy checker found no visible surface in any listed PII category, hiding place, or language. The final medical-probe result is 100%; no practice probe remained missing. Compilation and all **62 unit tests** passed.

## Equivalence classes and measured uniqueness

The same raw-input extractor and class-size method were applied before and after Phase 4 transformations. “Unique” means a record in a singleton equivalence class for the listed exact dimensions. The profile includes hospital; the extended profiles also include age, location tiers, PIN, stay, diagnosis, and event date. The month profile bins dates to year-month; the exact profile uses the released exact date. This is a measured dataset property, not a guarantee of anonymity.

| Combination | Before classes | Before singleton records (%) | Before below k=3 | After classes | After singleton records (%) | After below k=3 |
|---|---:|---:|---:|---:|---:|---:|
| Age + geography + hospital | 103 | 58 (7.06%) | 130 | 72 | 35 (4.26%) | 83 |
| Extended profile, event month | 179 | 109 (13.26%) | 185 | 260 | 177 (21.53%) | 271 |
| Extended profile, exact shifted date | 409 | 353 (42.94%) | 451 | 368 | 306 (37.23%) | 410 |

The age/geography/hospital and exact-date profiles became less unique. The extended month profile became more unique after patient-specific shifting because different offsets moved records into different calendar months. This is a real adverse metric, not hidden by the aggregate report. Exact patient-level shifts preserve relative intervals, and those shifted dates remain quasi-identifiers when combined with diagnosis, hospital and other facts. Every profile still has singleton classes, so Phase 4 does not establish anonymity.

The report also records median class sizes. Before/after: age/geography/hospital 1.0/2.0; extended month 1.0/1.0; extended exact date 1.0/1.0. Minimum class size is 1 for every profile.

## Transformations and date consistency

Action counters are field actions, not patient counts:

- 694 event-date values were shifted for resolved patients using a patient pseudonym and the `RAKSHA_SECRET` HMAC key. The same patient-derived day offset is applied across records and hospitals; calendar arithmetic preserves intervals and handles leap days and calendar boundaries.
- 76 event-date values for unresolved records were generalized to month precision. Those records do not receive a shared guessed shift, so their cross-file intervals are not guaranteed.
- 84 age values were generalized. Default bands keep minors distinct (`0–4`, `5–9`, `10–14`, `15–17`), use five-year adult bands, and use `85+` for seniors. Tests check the reported age is within the band.
- 31 location values were generalized to an existing coarser geography; 106 address/location values were suppressed where no safe parent location existed. Hospital ward labels and aggregate ward census entries are retained as clinical/facility context.
- 92 PIN values were reduced to a three-digit prefix. 20 FHIR address PINs remain masked to preserve the earlier address contract.
- 103 DOB values were suppressed. Stay durations are bucketed only when a record remains below the configured minimum class size and an explicit duration field is available.
- `records_generalized`: 438; `records_suppressed`: 155. These count records with at least one corresponding action; `report.json` also contains raw-value-free action totals.

Synthetic tests confirm same-patient cross-hospital date consistency, preservation of a five-day interval, different patients/secrets deriving different offsets, leap-year handling, month/year boundaries, unresolved-date generalization, date values in named and loosely named JSON metadata, and exact-date removal from output filenames.

## Diagnosis policy and clinical integrity

An initial Phase 4 run generalized 14 coded diagnosis values and the practice checker consequently lost 21 probes (14 diagnosis probes and 7 hospital ward/context probes). Those cases were inspected and corrected. The final policy preserves exact diagnoses by default because the checker counts exact diagnosis codes as medical probes and free-text diagnoses cannot safely be mapped to a broader concept without an ontology. `rare_diagnosis_action` is configurable; `generalize`/`suppress` are opt-in and should only be used where the consuming clinical contract allows the loss of detail. Generalization is implemented only for coded diagnosis values. No free-text diagnosis is blindly replaced.

The final checker preserved every diagnosis, procedure, medicine, dose, frequency, duration, unit, vital, lab value, clinical phrase, doctor name, and hospital ward probe. No clinical preservation false positives remained in the official practice probes. Focused tests cover explicit rare coded diagnosis policy, default diagnosis preservation, common clinical values, and the hospital-ward distinction.

## Tests and commands

Added focused synthetic tests for HMAC shift consistency/secret rotation, cross-hospital linked records, leap days and calendar boundaries, unresolved records, metadata dates, filename dates, age bands, location and PIN generalization, stay buckets, coded rare-diagnosis handling, equivalence-class aggregation, medical-value preservation, and avoidance of raw values in reports.

Final commands run from `doctor/`:

```text
python3 -m unittest discover -s tests -q
python3 -m compileall -q src tests
RAKSHA_SECRET='phase4 evaluation secret 2026' python3 main.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase4-out
python3 .local-evaluation/official-kit/validate_output.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase4-out
python3 .local-evaluation/official-kit/check_dev.py --output /private/tmp/raksha-phase4-out
python3 .local-evaluation/official-kit/check_submission.py --repo . --run
```

Results: 62/62 tests passed; compilation passed; `CONTRACT OK`; 0/3,230 PII surfaces visible; 0/4 canaries visible; 4,855/4,855 medical probes preserved; precision 1.00, recall 0.26, F0.5 0.63, zero wrong merges; and `READY TO SUBMIT`. The submission checker also verified deterministic same-secret output, changed output after secret rotation, no secret in outputs/logs, and unchanged input files. The checker labels the practice scanned-discharge PDF as a Project Brief PDF; as noted in Phase 3, that is a fixture false positive and does not verify a real brief.

## Remaining risks and limits

- Month-level extended-profile uniqueness increased from 13.26% to 21.53% after shifting. This demonstrates that deterministic date shifting alone can move records into less common combinations. Exact-date uniqueness improved but remains 37.23%; all dimensions still need to be considered together.
- 203 of 822 records were unresolved by Phase 3 linkage. Their dates are month-generalized without patient-level interval consistency. More robust identity evidence can improve date consistency, but linkage recall remains 0.26 and is unchanged.
- The default diagnosis policy preserves rare diagnoses to maintain exact medical values. Rare disease plus hospital, date and other quasi-identifiers may still be identifying; generalized diagnosis handling is opt-in and can reduce clinical fidelity.
- Hospital and some coarse geography remain in output. PIN prefixes and shifted dates can still contribute to unique combinations. The measurement uses only extracted fields and this practice dataset; it does not simulate all attacker knowledge.
- Strict full-date values are handled even in loosely named JSON metadata. Dates embedded in arbitrary prose or encoded non-text payloads may not be found by the Phase 4 date extractor. Unsupported files continue to be quarantined under the existing pipeline behavior.
- No measured low-risk percentage guarantees anonymity or resistance to linkage with external registries.

## Completion status

Phase 4 is implemented and evaluated. No Phase 5 work was started. Changes remain uncommitted as requested; no commit or push was made.
