# Phase 4 Plan — Advanced Privacy Protection and Re-identification Risk

## Audit completed before implementation

The requested PRD was read in full (`prd.md`; this workspace keeps the file lowercase). The complete Phase 2.1 evaluation, Phase 3 plan and Phase 3 evaluation were read, along with current privacy-relevant code, official practice attack documentation and the read-only starter helpers.

### Current implementation

- `src/pipeline.py` performs direct PII redaction and applies Phase 3 pseudonyms. It has no quasi-identifier transformation pass. The `records_generalized` and `records_suppressed` counters are hard-coded to zero.
- `config/policy.yaml` only configures maximum file size and JSON depth. There is no `src/privacy/` package.
- `src/linkage/extractor.py` captures names, IDs, age, DOB and some location signals for linkage, but not the patient-scoped date, duration and diagnosis field paths needed for privacy transformations.
- `src/detection/medical.py` protects clinical spans. Any Phase 4 changes must avoid rewriting diagnosis, procedure, medicine, frequency, dose, vital, lab and unit values unless a measured high-risk policy specifically generalizes a quasi-identifier such as a rare diagnosis.
- `transform_file()` already has exact CSV/TSV row locators, JSON record paths and document locators for text/FHIR. JSON cleaning is recursive but does not currently retain paths during cleaning. A locator-aware overlay is the least disruptive integration point.
- The policy loader accepts simple scalar YAML entries only. Phase 4 settings should therefore remain scalar/configurable without introducing an unneeded YAML dependency, or the loader and tests must be expanded explicitly.

The copied practice input includes CSV/TSV, JSON, text, FHIR Bundles and quarantined unsupported files. A metadata-only inventory found date/admission/discharge/visit fields, age/sex and DOB fields, location fields, diagnosis and duration fields; Phase 4 must cover both labeled structured values and anchored text dates/ages. No practice identity or canary may be added to production rules.

## Baseline measured before implementation

Commands run from `doctor/`:

```text
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -q
RAKSHA_SECRET='phase4 baseline secret' python3 main.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase4-before
python3 .local-evaluation/official-kit/validate_output.py --input .local-evaluation/official-kit/dev/input --output /private/tmp/raksha-phase4-before
python3 .local-evaluation/official-kit/check_dev.py --output /private/tmp/raksha-phase4-before
```

Baseline: 49/49 tests passed, compilation passed, `CONTRACT OK`, 0/3,230 PII surfaces visible, 0/4 canary surfaces visible, 4,855/4,855 medical probes preserved, linkage precision 1.00 / recall 0.26 / F0.5 0.63, and zero wrong merges. Pipeline output: 200 files (193 sanitized, 7 quarantined), 822 locators. Phase 3 evaluation documents the previous baseline.

## Proposed design

### 1. Patient-consistent date handling

- Add `src/privacy/` with a dedicated HMAC date-shift derivation using a versioned domain distinct from pseudonym generation. Derive the offset from the patient pseudonym (which is already a keyed stable value), use the same offset for all date values in every linked file, and never persist raw identities, anchors, offsets or the secret.
- Shift admission, discharge, encounter, visit, observation and other clinical dates with one signed whole-day offset per linked patient. Use calendar arithmetic so leap days and month/year boundaries work, preserve date-only versus timestamp shape and preserve every within-patient interval.
- Exact DOB is suppressed as direct identifying information; it is not treated as an encounter date. Existing age, when present, is generalized independently.
- For records whose patient is unresolved, do not invent a shared patient key or reuse an unkeyed/global offset. Generalize exact clinical dates to month-level precision in a deterministic, format-aware way. This sacrifices day-level intervals only where linkage itself is unresolved; record the action in the aggregate report and document this boundary.
- Keep date parsing limited to validated date-shaped values in date-like fields/anchors and strict full-date values in loosely named JSON metadata, not arbitrary numbers, diagnoses, dose strings or clinical measurements. Preserve timezone and timestamp suffixes when shifting timestamps. Embedded date prose in unstructured metadata remains a limitation.

### 2. Age and location generalization

- Add configurable truthful age bands: default five-year bands, explicit child bands, and an open-ended upper senior band. The actual age must be inside every emitted band. Extract age from age-labeled scalar fields/text, including `age/sex` forms, while avoiding durations and lab reference ranges.
- Suppress DOB values. Do not infer an exact age from DOB unless an event date is available and the policy can produce only a truthful age band.
- Generalize village/locality to a coarser location already present in the same record (tehsil, then district); if no safe parent is present, suppress the village/locality. Remove house and landmark details. Reduce PIN to a configurable prefix; suppress it for FHIR address values where the existing address contract already required masking. Keep hospital ward labels as care-location/clinical context rather than residential locality, including aggregate ward census values.
- Keep district/tehsil where measured combinations remain sufficiently broad. Do not fabricate geography or use a practice-only gazetteer.

### 3. Risk-based rare-value handling

- Extract privacy-safe quasi-identifier features per record: age band, location tier, shifted/partial dates, stay-duration bucket, diagnosis category, and hospital. Preserve source paths in memory only so edits target the correct record field.
- Calculate equivalence-class sizes before and after sanitization using configured combinations and `minimum_k` (initial target k=3). Report record count, singleton count/percentage, minimum/median class size, and class-size buckets; write no quasi-identifier values or class members to `report.json`.
- Apply transformations to direct location detail, age precision, PIN, and stay-duration precision where policy allows. The default is `rare_diagnosis_action: preserve`: the practice checker treats exact diagnosis codes as medical probes, and there is no safe broadening for arbitrary free-text concepts. Configurable `generalize` and `suppress` modes are opt-in where the clinical contract permits diagnosis changes; only coded diagnoses have an implemented broader category. Record action counts by category, never raw values.
- Keep the risk analyzer's measurements explicit: this is a release equivalence-class analysis against the listed fields, not proof of anonymity and not a substitute for the organizer's full hidden attacker.

### 4. Pipeline integration and contract safety

- Build a Phase 4 transformation plan after Phase 3 linkage, keyed by `(input file, locator)`. Apply it during format-aware serialization without changing locators or the `records.jsonl` schema.
- Preserve CSV/TSV columns and JSON/FHIR structure. Do not add arbitrary pseudonym keys or restore source values. If a required transformation cannot be safely applied, quarantine that file or conservatively suppress the affected value.
- Count generalized and suppressed records from actual actions. Add only aggregate risk and action summaries to `report.json`; retain existing report keys and the organizer contract.
- Do not modify `.local-evaluation/official-kit/`.

## Planned regression coverage

Tests will cover HMAC shift consistency across linked records/hospitals, independent patients, secret rotation, leap years and calendar boundaries, unresolved date month-generalization, age-band truth and child/senior edges, location hierarchy/PIN reduction, diagnosis preservation and rare-diagnosis fallback, equivalence-class calculations, CSV/TSV/JSON/text/FHIR path edits, metadata dates, absence of original dates/addresses/secrets from output/logs, and Phase 1–3 privacy/linkage/medical regression.

## Evaluation plan

After implementation, rerun compilation, the full unit suite, output validator, official submission checker and full practice privacy/linkage checker. Compare the Phase 3 baseline against final output for PII leakage, canaries, medical probes, linkage precision/recall/F0.5/false merges, records generalized/suppressed, age/location transformation correctness, date-shift determinism/interval preservation, and equivalence-class sizes/uniqueness. Create `docs/PHASE4_EVALUATION.md` with actual values, failed cases and residual risk. Phase 5 is out of scope until this evaluation is complete.

## Known design trade-offs to evaluate

- Patient-level date shifts preserve all event intervals, so stay length may remain identifying. The policy will generalize explicit stay duration only when a measured rare combination remains risky; the risk report must state that exact intervals can still disclose stay length.
- Month-level generalization for unresolved identities protects exact visit days but cannot preserve cross-file timelines when identity cannot be established. This is intentionally safer than pretending those records share a patient shift.
- The current resolver links only 619 of 822 practice locators. Date-shift quality and the equivalence analysis must clearly separate linked patient-level handling from unresolved record-level handling.
