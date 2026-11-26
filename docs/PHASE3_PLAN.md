# Phase 3 Plan — Conservative Linkage and Keyed Pseudonyms

## Audit findings

The Phase 2.1 implementation already parses CSV, TSV, nested JSON, FHIR Bundles, and text into output locators. CSV/TSV records use zero-based `row:N`; JSON arrays use JSON Pointers; text and FHIR Bundles use `doc`. However, `_json_records` only recognizes top-level arrays of objects, FHIR Bundles are intentionally represented as one document, and every current `records.jsonl` entry has `patient: null`. There is no linkage module or pseudonym generation. `report.json` currently sets `records_linked` to zero.

Input identity evidence is accessible in memory before sanitization: table headers and rows, JSON values and field context, FHIR Patient resources and identifiers, text detections, and original filenames. The pipeline currently sanitizes each file while it writes it, so Phase 3 must add a dataset-wide extraction and resolution pass before that write loop. Identity evidence and match explanations must remain memory-only.

The organizer contract requires one `records.jsonl` entry per patient-bearing record, the same pseudonym in that exported record, `null` when not linked, the sanitized output path, and an input locator. Its checker uses the longest locator reported for a file. For text/FHIR, `doc` is the locator. The official practice checker computes pairwise precision, recall, F0.5 and false merges from mapped records; it does not award a link merely because a pseudonym is present. The organizer's dataset rules consider records linkable only through a patient-unique strong identifier or the same name plus a unique second clue (DOB, relative, or village plus age within one year). Similar names or demographic resemblance alone are insufficient.

The current practice baseline was rerun before Phase 3 work:

- 0/3,230 direct PII surfaces visible.
- 0/4 canary surfaces visible.
- 4,855/4,855 medical preservation probes retained.
- `CONTRACT OK`; 200 files accounted for (193 sanitized, 7 quarantined), 822 locators emitted.
- Linkage: precision 0.00, recall 0.00, F0.5 0.00, with no false merges because no records are linked.

Truth-file profiling for evaluation only found 771 link-required record units for 48 synthetic patients, 110 units without required links, and two ambiguous units. Required units span CSV, TSV, JSON, and text/FHIR. The answer key is evaluation-only and will not be read by production code.

## Design

### 1. Dataset-wide record extraction

Add a dedicated `src/linkage/` package. A record candidate carries only an in-memory file/locator reference, an input format and field-path map, plus normalized evidence. Extract records in stable path/locator order before sanitization. Keep source values in memory only for the duration of the run; do not serialize candidate records, raw mappings, or decision evidence.

- CSV/TSV: extract each data row by header; preserve `row:N` alignment.
- JSON: extract records at the same JSON Pointers the pipeline exports; recursively inspect their patient identity fields without treating clinical-resource names as patient names.
- FHIR Bundle: resolve internal Patient resources and references, then treat the Bundle as one exported `doc` record.
- Text: use explicit patient/name/ID/relationship labels and existing detector categories; do not infer a patient from an arbitrary provider, relative, diagnosis, or filename alone.
- A file-level candidate can be linked only when the document has patient-specific evidence. Clean reference documents and unrelated files stay unlinked.

### 2. Normalized evidence and candidate blocking

Represent identifiers with category and issuer/system namespace. Normalize case, Unicode digits, punctuation, phone country prefixes, common ID separators and name transliteration. Retain original spans/field paths separately so output edits are applied to the original text and exact clinical values are not normalized.

Block comparisons through indexed evidence keys rather than all-record pairwise comparison: exact reliable identifiers, normalized/transliterated name tokens, phone, and name-plus-age/DOB/relative/location keys. Short/common names and shared household phones create candidates only; they are never proof on their own. Use the existing Devanagari key helper plus small generic spelling/phonetic variants; do not add practice names or canaries.

### 3. Conservative decision and clustering

Each candidate pair gets an internal decision with evidence codes, confidence, and a state (`match`, `no_match`, or `ambiguous`). Evidence will be category-aware:

- A unique exact Aadhaar/ABHA/PAN/email or explicitly patient-scoped identifier is strong evidence. Hospital-local identifiers are namespaced; two different hospital IDs are not automatically a contradiction across hospitals.
- A shared phone is strong only when unique to one patient in the run or corroborated by patient name and another independent clue. A phone shared across conflicting names/records cannot merge by itself.
- A same-name candidate needs an independent, sufficiently specific second clue and a uniqueness check over the candidate population.
- Contradictory same-issuer identifiers, incompatible DOBs, or incompatible well-supported identities block a merge.
- Ambiguous pairs remain separate and unlinked. Thresholds favor precision and are configured and measured, not tuned to maximize raw recall alone.

Clusters are built deterministically from accepted edges. Before union, validate strong-identifier and demographic contradictions across the complete proposed cluster; do not allow a weak A–B and B–C chain to overrule an A–C contradiction. Keep `LinkDecision` and cluster explanations in memory only.

### 4. HMAC pseudonyms

Add a dedicated pseudonymizer using HMAC-SHA256, explicit versioned domain separation, and a non-sequential, sufficiently long encoded digest. Reject missing, whitespace-only, or too-short secrets; choose a minimum compatible with the organizer's generated checker secrets and verify it in the official submission checker. Never fall back to plain hashing or a generated default. Derive a deterministic cluster anchor from the strongest stable evidence available, HMAC it with `RAKSHA_SECRET`, and discard the raw anchor after the run. No raw-to-pseudonym map, cluster key, or evidence is written to files or logs.

### 5. Applying pseudonyms without losing records

Keep Phase 2.1 redaction and medical-protection logic intact. Add a separate, locator-aware output overlay after detection:

- In tables, replace a patient-scoped identifier/name cell with the pseudonym where possible; preserve the existing columns and delimiter.
- In JSON, replace a patient-scoped identity value or identifier with the pseudonym without changing clinical fields or unrelated practitioner/relative identities.
- In FHIR, place the pseudonym in the Patient identifier while preserving valid bundle references and clinical resource values.
- In text, replace only the explicitly resolved patient identity span; if there is no safe replaceable span, add a clearly labeled pseudonym to the document while preserving its clinical text.
- `records.jsonl` carries the same pseudonym, or `null` for unresolved records. Locators must still point to the original record and sanitized output file.

This overlay must never restore or emit raw names or identifiers. Test that every non-null record pseudonym is present in the corresponding exported record, and that all raw identifier surfaces remain absent.

## Adversarial verification

Add synthetic tests for all requested cases: exact shared identifiers across hospitals; same identity with alternate spellings, Devanagari/Latin/Hinglish and transliteration; two people with identical or similar names; shared family phone; conflicting same-issuer identifiers; missing and insufficient evidence; multiple records per cluster; deterministic HMAC stability; secret rotation; unique pseudonyms for different clusters; and no raw evidence in outputs/logs. Include cross-format table/JSON/text/FHIR cases, locator assertions, clinical preservation, and unresolved-null behavior.

Evaluate with both unit tests and the official checker. Report pairwise precision/recall/F0.5, false merges, missed linkable pairs, linked and unresolved record counts, and pseudonym consistency. Independently verify same-secret stability and different-secret change. Inspect every false merge and missed-link category; do not use practice truth as production input or hardcode any practice identity.

## Scope boundary and risks

This phase adds linkage and keyed pseudonyms only. Date shifts, age bands, location generalization, rare-attribute risk analysis, and Phase 4 work remain out of scope. Main risks are household phone reuse, common names, cross-script transliteration collisions, hospital-local identifier collisions, inconsistent field context, and pseudonym insertion changing a protected clinical span. We will prefer null links over unsupported merges and rerun all Phase 2.1 checks after each integration change. The official organizer kit is read-only and will not be modified.

## Evaluation outcome

Implementation and evaluation are complete. The final practice run retained 0/3,230 visible PII and 0/4 visible canary surfaces, retained 4,855/4,855 medical probes, and achieved linkage precision 1.00, recall 0.26, F0.5 0.63 with zero wrong merges. The final workspace emitted 822 locators, with 619 pseudonymized records and 203 unresolved records. The full measurements, checks, missed-link limitations, and remaining risks are in [PHASE3_EVALUATION.md](PHASE3_EVALUATION.md).
