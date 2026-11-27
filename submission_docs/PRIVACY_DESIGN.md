# Privacy Design

## Detection and clinical preservation

`src/detection/` normalizes multilingual text and applies explainable, deterministic rules for names, Indian identifiers, contact information, and address-related values. Context and dataset-local labeled-name evidence help distinguish patient and relative names from clinicians and clinical text. A dedicated medical-value layer protects medicines, doses, frequencies, diagnoses, procedures, vitals, laboratory values, units, and durations from ordinary PII rules. The pipeline applies findings through format-specific transformations rather than deleting whole records.

The tested practice profile is English, Hindi/Devanagari, and Hinglish. Detection is rule/context based; it is not a general-purpose named-entity model. Novel spellings, unrecognized schemas, encoded or otherwise opaque content, and ambiguous free text can still evade detection or cause over-redaction.

## Linkage and pseudonyms

`src/linkage/` extracts identity evidence and compares records using conservative blocks, agreement, and conflict checks. Strong identifiers can support cross-hospital and cross-script linkage. Weak or conflicting evidence is rejected or left unresolved to limit false merges. Patient pseudonyms are derived using HMAC with a dedicated HKDF-separated key purpose and the runtime `RAKSHA_SECRET`; raw identifiers are not used as pseudonyms.

Practice linkage remains high precision and incomplete: precision 1.00, recall 0.36, F0.5 0.74, and zero observed wrong merges in the latest run. A narrowly scoped rule accepts an exact MRN within the same inferred hospital namespace when no contradictory DOB, global identifier, or incompatible name is present. Most name-only or otherwise weak pairs remain unresolved.

## Quasi-identifiers

The privacy layer generalizes age into truthful bands (including dedicated child and older-age bands), reduces location/PIN precision, and shifts identifiable dates by a deterministic patient-specific offset. Exact length-of-stay values are preserved by default to meet the clinical-integrity requirement; bucketing is available only as an explicit policy opt-in. Each patient's relative date intervals remain consistent across linked records. Unresolved identities receive conservative date precision. Rare diagnosis generalization is configurable and defaults to preserving clinical values.

The pipeline reports exact-equivalence-class sizes for declared combinations. These are diagnostic risk indicators, not proof of k-anonymity against arbitrary auxiliary data and not a guarantee of anonymity.

## Measured limits

Phase 6.1 found no reduction in broad singleton counts on its fixed generated datasets: 22/36 records (61.11%) before and after on the original set, and 36/36 (100%) on the varied set. Tested generalizations did not lower these counts without broader loss of information. Small generated datasets cannot establish anonymity or predict hidden-data performance. See [EVALUATION.md](EVALUATION.md) for current practice and independent-suite results.
