"""Explainable, confidence-scored multilingual PII detection rules."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from src.detection.medical import protected_spans
from src.detection.normalization import name_keys, normalize_text


@dataclass(frozen=True)
class Detection:
    start: int
    end: int
    category: str
    confidence: float
    method: str


_FIELD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ABHA_ADDRESS", re.compile(r"abha.*address|health.?id.?address", re.I)),
    ("ABHA_NUMBER", re.compile(r"abha|health.?id|health.?number", re.I)),
    ("AADHAAR", re.compile(r"aadhaar|aadhar|uidai", re.I)),
    ("PAN", re.compile(r"(?:^|[_\W])pan(?:$|[_\W])", re.I)),
    ("EMAIL", re.compile(r"email|e.?mail", re.I)),
    ("PHONE", re.compile(r"phone|mobile|contact|telephone|whatsapp|मोबाइल|फोन|संपर्क", re.I)),
    ("INSURANCE_ID", re.compile(r"insurance|policy|claim.?id|claim.?no|insurer|member.?no|member.?id|scheme|coverage|pmjay|ayushman|health.?card|ration.?card|benefit.?id|बीमा|पॉलिसी", re.I)),
    ("MRN", re.compile(r"^identifier$|mrn|uhid|\bpatient[ _-]*(?:id|ref|reference|identifier|number|no)\b|medical.?record|identifier|record.?no|registration.?no|reg.?no|ipd.?no|opd.?no|encounter.?no|admission.?no|hospital.?(?:uhid|mrn|no)|accession.?(?:id|no|number)|visit.?(?:id|no|number)", re.I)),
    ("DOB", re.compile(r"date.?of.?birth|dob|birth.?date|जन्म.?तिथि|जन्म.?दिनांक|जन्म.?तारीख|janm.?tithi", re.I)),
    ("PIN", re.compile(r"^pin$|pin.?code|pin.?no|postal.?code|zip(?:.?code)?|pincode|post.?code|पिन.?कोड", re.I)),
    ("HOUSE", re.compile(r"^house$|house.?no|h.?no|flat.?no|makaan|makan|ghar|मकान|घर.?नंबर|घर.?नं|गृह.?संख्या|मकान.?नंबर", re.I)),
    ("LOCALITY", re.compile(r"locality|mohalla|colony|ward.?address|ilaaka|basti|मोहल्ला|मुहल्ला|इलाका|क्षेत्र|वार्ड|टोला|शहर|जिला|ज़िला|राज्य", re.I)),
    ("VILLAGE", re.compile(r"village|gram|gaon|गांव|गाँव|ग्राम|मौजा", re.I)),
    ("LANDMARK", re.compile(r"landmark|near.?by|nishan|पास.?में|नज़दीक|निशान", re.I)),
    ("ADDRESS", re.compile(r"address|addr|residence|street|pata|पता", re.I)),
    ("RELATIVE_NAME", re.compile(r"relative|guardian|next.?of.?kin|father|mother|husband|wife|(?:^|\s)(?:pita|pati|patni|beta|beti|putra|putri)(?:\s|$)|s/o|d/o|w/o|c/o|son.?of|daughter.?of|पिता|पुत्र|पुत्री|पति|पत्नी", re.I)),
    ("PATIENT_NAME", re.compile(r"patient.?name|full.?name|first.?name|last.?name|given.?name|family.?name|beneficiary.?name|member.?name|surname|^name$|^naam$|नाम|रोगी|मरीज", re.I)),
    ("PATIENT_NAME", re.compile(r"^(?:author|created.?by|updated.?by|uploaded.?by|raised.?by|reported.?by|entered.?by|submitted.?by|sender|recipient|contact.?person)$", re.I)),
    ("METADATA", re.compile(r"^(?:source.?path|source.?file|origin.?path|import.?path|export.?path|file.?path|attachment.?path)$", re.I)),
)
_MEDICAL_FIELD = re.compile(r"doctor|physician|provider|clinician|medicine|drug|dose|frequency|diagnosis|disease|symptom|complaint|lab|vital|procedure|treatment|history|hospital|facility|clinic|department|ward|range|reference", re.I)

_PHONE = re.compile(r"(?<!\d)(?:\+?91[\s().-]?)?(?:0[\s().-]?)?[6-9](?:[\d\s().-]{7,14})\d(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)(?:\d[\s-]?){11}\d(?!\d)")
_ABHA = re.compile(r"(?<!\d)(?:\d[\s-]?){13}\d(?!\d)")
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.I)
_PIN = re.compile(r"(?<!\d)[1-9]\d{5}(?!\d)")
_GENERIC_ID = re.compile(r"(?i)(?:\b(?:UHID|MRN|IPD|OPD|IP|ABHA|Patient\s*(?:ID|Ref(?:erence)?|Identifier|No|Number)|Medical\s*Record\s*(?:No|Number)|Reg(?:istration)?\s*(?:No|ID|Number)|Admission\s*(?:No|Number)|Encounter\s*(?:ID|No)|Case\s*(?:ID|No)|Visit\s*(?:ID|No|Number)|Accession\s*(?:ID|No|Number)|Hospital\s*(?:UHID|MRN|No|ID)|Insurance\s*(?:ID|No)|Policy\s*(?:No|ID)|Claim\s*(?:ID|No))\s*[:#./-]?\s*)([A-Z0-9][A-Z0-9./_-]{3,})")
_AADHAAR_LABEL = re.compile(r"(?i)(?:aadhaar|aadhar|uid)\s*(?:no|number|id)?\s*[:#-]?\s*((?:\d[\s-]?){11}\d)")
_ABHA_LABEL = re.compile(r"(?i)(?:abha(?:\s*(?:address|number|id))?|health\s*id)\s*[:#-]?\s*([\w.@-]{6,})")
_EMAIL_LABEL = re.compile(r"(?i)(?:e-?mail)\s*[:=]\s*([^\s,;]+)")
_PHONE_LABEL = re.compile(r"(?i)(?:phone|mobile|contact|whatsapp|फोन|मोबाइल|संपर्क)\s*(?:no|number)?\s*[:=.-]?\s*([+\d(][\d\s().+-]{7,16}\d)")
_NAME_LABEL = re.compile(
    r"(?i)(?:patient(?:'s)?\s*name|patient|pt\.?|full\s*name|name|रोगी\s*का\s*नाम|मरीज\s*का\s*नाम|नाम|रोगी|मरीज)\s*[:=#-]\s*"
    r"([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,3})"
)
_HONORIFIC_NAME = re.compile(r"(?i)(?:\b(?:mr|mrs|ms|shri|smt|mohd)\.?|श्री|श्रीमती|श्रीम|मोहतरमा)\s+([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})")
_NAME_HONORIFIC_SUFFIX = re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})\s+(?:ji|sahab|sahib|didi|bibi|बेगम|जी|साहब)\b")
_NAME_AGE = re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})\s+\d{1,3}\s*(?:y|yr|yrs|year|years)?\s*[/,-]\s*[mf]\b")
_NAME_LABEL_REPORT_OF = re.compile(r"(?i)\breport\s+of\s+([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})(?=\s+(?:age\s*)?\d|[,;:]|$)")
_NAME_BEFORE_RELATION = re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})\s*,?\s+(?:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|son\s+of|daughter\s+of|wife\s+of|husband\s+of|के\s+पुत्र|की\s+पत्नी)\b")
_HINDI_PATIENT_OBJECT = re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:[ \t]+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})[ \t]+को[ \t]+(?:(?:आज|कल|पिछले[ \t]+दिन|अभी)[ \t]+)?(?:(?:\d+[ \t]*(?:दिन|हफ्ते|सप्ताह|महीने)[ \t]*(?:से|के))|(?:बुखार|दर्द|खांसी|उल्टी|दिखाया|भर्ती|इलाज|जाँचा[ \t]+गया|जांचा[ \t]+गया|जांच[ \t]+की|जांच[ \t]+के[ \t]+लिए|परीक्षण[ \t]+किया))")
_HINGLISH_PATIENT_NOTE = re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})(?:\s+(?:ji|sahab|babu|bhai|didi|behenji|amma|भैया|बहनजी))?\s+(?:ka|ki|ke)\s+(?:bp|pulse|bukhar|dard|khansi|sugar|ulti)\b")
_NAME_BEFORE_KNOWN_HISTORY = re.compile(r"(?i)([A-Z][A-Z.'’\-]*(?:\s+[A-Z][A-Z.'’\-]*){1,2})\s*[-–]\s*k\s*/\s*c\s*/\s*o\b")
_KINSHIP_SUFFIX = re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2}\s+(?:bhaiya|bhai|behenji|behen|didi|chachu|chacha|mama|mami|mausa|mausi|papa|pitaji|amma|nana|nani|dada|dadi|kaka|kaki|भैया|भाई|बहनजी|बहन|चाचा|चाचू|मामा|मामी|पापा|अम्मा|नाना|नानी|दादा|दादी))\b")
_PERSON_ROLE_NAME = (
    re.compile(r"(?i)(?:called\s+by|witnessed\s+by|signed\s+by|accompanied\s+by|reported\s+by|attendant|visitor|caregiver|informant|guardian|relative|अभिभावक|परिजन|साथ\s+आए|देखभालकर्ता|आगंतुक)\s*[:=,-]?\s*([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})"),
    re.compile(r"(?i)([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})\s*\(\s*(?:attendant|visitor|caregiver|informant|guardian|relative)\b"),
)
_RELATION = re.compile(
    r"(?i)(?<!\w)(?:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|c\s*/\s*o|son\s+of|daughter\s+of|wife\s+of|husband\s+of|father\s+of|mother\s+of|guardian(?:\s+of)?|father\s+(?:name|naam)|mother\s+(?:name|naam)|husband\s+(?:name|naam)|wife\s+(?:name|naam)|pita(?:ji)?|pati(?:dev)?|patni|beta|beti|putra|putri|walad|ke\s+putra|ki\s+putri|ka\s+beta|ki\s+beti|पति|पिता|पुत्र|पुत्री|पत्नी|के\s+पुत्र|की\s+पत्नी|का\s+बेटा|की\s+बेटी)(?=\s|[:.-])\s*[:.-]?\s*(?:(?:of|name|naam)\s*[:=-]?\s*)?"
    r"([A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2})"
)
_ADDRESS_LABEL = re.compile(r"(?i)(?:address|residence|pata|घर\s+का\s+पता|पता)(?:\s*\([^\n)]*\))?\s*[:=]\s*([^\n;|]+)")
_PIN_LABEL = re.compile(r"(?i)(?:pin(?:\s*code)?|postal\s*code|zip(?:\s*code)?|pincode|पिन\s*कोड)\s*[:#-]?\s*([1-9]\d{5})")
_DOB_LABEL = re.compile(r"(?i)(?:date\s*of\s*birth|dob|birth\s*date|जन्म\s*तिथि|जन्म\s*दिनांक)\s*[:#=-]?\s*(\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}-\d{2}-\d{2})")
_CONTEXT_LABELS = (
    ("HOUSE", re.compile(r"(?i)(?:house|h\.?\s*no\.?|flat\s*no|makaan|makan|ghar|मकान|घर\s*(?:नंबर|नं)|गृह\s*संख्या)\s*[:=#-]\s*([^,;|\n]+)")),
    ("LOCALITY", re.compile(r"(?i)(?:locality|mohalla|colony|ward\s*area|ilaaka|basti|मोहल्ला|मुहल्ला|इलाका|क्षेत्र|वार्ड|टोला)\s*[:=#-]\s*([^,;|\n]+)")),
    ("VILLAGE", re.compile(r"(?i)(?:village|gram|gaon|gaav|jila|zilla|गांव|गाँव|ग्राम|मौजा|जिला|ज़िला)\s*[:=#-]\s*([^,;|\n]+)")),
    ("LANDMARK", re.compile(r"(?i)(?:landmark|near\s+to|nearby|nishan|paas\s+mein|nazdeek|पास\s+में|नज़दीक|निशान)\s*[:=#-]?\s*([^,;|\n]+)")),
    ("INSURANCE_ID", re.compile(r"(?i)(?:insurance|policy|claim|pmjay|ayushman|health\s*card|ration\s*card|बीमा|पॉलिसी)\s*(?:id|no|number|card)?\s*[:=#-]\s*([A-Z0-9][A-Z0-9/_-]{3,})")),
)
_FILE_ID = re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{2,8}[-_/]\d{2,}(?:[-_/]\d{2,})+(?![A-Z0-9])|(?<![A-Z0-9])[A-Z]{2,8}[-_/]\d{4,}(?![A-Z0-9])|(?<![A-Z0-9])[A-Z]{2,6}\d{4}[-_/]\d{4,}(?![A-Z0-9])|(?<![A-Z0-9])[A-Z]{2,6}\d{6,}(?![A-Z0-9])")
_HOUSE = re.compile(r"(?i)\b(?:h\.?\s*no\.?|house\s*(?:no|number)|flat\s*(?:no|number))\s*[:#.-]?\s*([\w/-]+)")
_MEDICAL_WORDS = re.compile(r"(?i)\b(?:fever|bukhar|dengue|diabetes|malaria|cough|pain|दर्द|बुखार|डेंगू|मधुमेह|खांसी)\b")
_IDENTITY_CUE = re.compile(
    r"(?i)(?:patient(?![A-Za-z])|pt\.?(?![A-Za-z])|resident(?![A-Za-z])|beneficiary(?![A-Za-z])|member(?![A-Za-z])|claimant(?![A-Za-z])|insured(?![A-Za-z])|subject(?![A-Za-z])|name(?![A-Za-z])|naam|रोगी|मरीज|नाम|"
    r"relative|guardian|attendant|visitor|caregiver|informant|called\s+by|witnessed\s+by|signed\s+by|accompanied\s+by|अभिभावक|परिजन|देखभालकर्ता|आगंतुक|"
    r"father\s+of|mother\s+of|husband\s+of|wife\s+of|son\s+of|daughter\s+of|s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|c\s*/\s*o|"
    r"पिता|पुत्र|पुत्री|पति|पत्नी|के\s+पुत्र|की\s+पत्नी|[-–]\s*k\s*/\s*c\s*/\s*o|\b(?:ka|ki|ke)\s+(?:bp|pulse|bukhar|dard|khansi|sugar|ulti)\b)"
)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/])")
_TOKEN = re.compile(r"[A-Za-z0-9\u0900-\u097f]+")
_SCHEMA_WORDS = {
    "patient", "name", "first", "last", "full", "given", "family", "phone", "mobile", "contact",
    "address", "date", "birth", "dob", "age", "sex", "gender", "diagnosis", "medicine", "drug",
    "dose", "frequency", "hospital", "doctor", "record", "id", "mrn", "uhid", "lab", "test",
    "result", "blood", "pressure", "village", "district", "city", "pin", "code", "ward", "house",
    "relative", "guardian", "father", "mother", "husband", "wife", "insurance", "policy", "claim",
    "department", "procedure", "history", "symptom", "complaint", "unit", "value", "reference",
    "stay", "duration", "length",
    "source", "path", "metadata", "meta", "author", "created", "updated", "uploaded", "raised",
    "reported", "entered", "submitted", "by", "sender", "recipient", "attendant", "visitor",
    "caregiver", "informant", "city", "town", "district", "state", "zip", "postal", "pmjay",
    "relative", "guardian", "source_path", "origin_path", "file_path", "relative_name",
    "ref", "patient_ref", "patient_reference", "accession", "visit", "identifier",
}
_NAME_SPELLINGS = {
    "mohammad": ("mohammad", "mohammed", "muhammad", "mohd", "md"),
    "mohammed": ("mohammad", "mohammed", "muhammad", "mohd", "md"),
    "muhammad": ("mohammad", "mohammed", "muhammad", "mohd", "md"),
}


def field_category(field_name: str) -> str | None:
    field = re.sub(r"[_\W]+", " ", normalize_text(field_name), flags=re.UNICODE).strip()
    # Strong identifiers keep priority over broad medical resource words such
    # as "hospital" (e.g. hospital_uhid is still a direct identifier field).
    for category, pattern in _FIELD_PATTERNS:
        if category in {"ABHA_ADDRESS", "ABHA_NUMBER", "AADHAAR", "PAN", "EMAIL", "PHONE", "INSURANCE_ID", "MRN", "DOB", "PIN"} and pattern.search(field):
            return category
    if _MEDICAL_FIELD.search(field):
        return None
    for category, pattern in _FIELD_PATTERNS:
        if pattern.search(field):
            return category
    return None


def is_medical_field(field_name: str) -> bool:
    if field_name.casefold().startswith("__clinical_resource__"):
        return True
    return bool(_MEDICAL_FIELD.search(field_name))


def _is_known_case_of_prefix(text: str, start: int) -> bool:
    """K/C/O means known case of, not care-of relative."""
    return bool(re.search(r"(?i)\bk\s*/\s*$", text[max(0, start - 8):start]))


class PIIDetector:
    """Detection engine with input-derived name candidates and protected spans."""

    def __init__(self) -> None:
        self._names: set[str] = set()
        self._known_names: set[str] = set()
        self._sensitive_values: dict[str, set[str]] = {}
        self._term_index: dict[str, list[tuple[tuple[str, ...], str]]] = {}
        self._index_dirty = True

    def _rebuild_term_index(self) -> None:
        if not self._index_dirty:
            return
        index: dict[str, set[tuple[tuple[str, ...], str]]] = {}
        for category, values in self._sensitive_values.items():
            for value in values:
                tokens = tuple(normalize_text(token) for token in _TOKEN.findall(value))
                if tokens:
                    index.setdefault(tokens[0], set()).add((tokens, category))
        for value in self._names:
            tokens = tuple(normalize_text(token) for token in _TOKEN.findall(value))
            if tokens:
                index.setdefault(tokens[0], set()).add((tokens, "PATIENT_NAME"))
        self._term_index = {
            first: sorted(terms, key=lambda item: (-len(item[0]), item[0], item[1]))
            for first, terms in index.items()
        }
        self._index_dirty = False

    def _lexicon_matches(
        self, text: str, require_context: bool = True, trusted_only: bool = False
    ) -> list[Detection]:
        self._rebuild_term_index()
        tokens = [(normalize_text(match.group()), match.start(), match.end()) for match in _TOKEN.finditer(text)]
        matches: list[Detection] = []
        for index, (token, start, _) in enumerate(tokens):
            for phrase, category in self._term_index.get(token, ()):
                if trusted_only and " ".join(phrase) not in self._known_names:
                    continue
                end_index = index + len(phrase)
                if end_index <= len(tokens) and tuple(item[0] for item in tokens[index:end_index]) == phrase:
                    end = tokens[end_index - 1][2]
                    # K/C/O is the clinical abbreviation "known case of";
                    # C/O itself is a relationship/complaint marker, not a name.
                    if re.fullmatch(r"(?i)(?:k\s*/\s*c(?:\s*/\s*o)?|c\s*/\s*o)", text[start:end]):
                        continue
                    if category in {"PATIENT_NAME", "RELATIVE_NAME"}:
                        # A learned identity is evidence only when the occurrence
                        # itself is near an explicit person/relationship cue.
                        # Repeated names in diagnoses, history and narrative
                        # prose are not automatically patient identifiers.
                        left = max(text.rfind("\n", 0, start), text.rfind(";", 0, start)) + 1
                        right_candidates = [pos for pos in (text.find("\n", end), text.find(";", end)) if pos >= 0]
                        right = min(right_candidates) if right_candidates else len(text)
                        window_start, window_end = max(left, start - 72), min(right, end + 72)
                        context = text[window_start:window_end]
                        if require_context and not _IDENTITY_CUE.search(context):
                            continue
                        method = "contextual_name_lexicon" if require_context else "opaque_attachment_name_lexicon"
                        confidence = 0.91 if require_context else 0.82
                        if trusted_only:
                            method = "trusted_identity_lexicon"
                            confidence = 0.89
                    else:
                        method = "input_value_lexicon"
                        confidence = 0.86
                    matches.append(Detection(start, end, category, confidence, method))
        return matches

    def _record_patient_matches(self, text: str, names: tuple[str, ...]) -> list[Detection]:
        """Match only the patient identity attached to the current JSON record."""
        tokens = [(normalize_text(match.group()), match.start(), match.end()) for match in _TOKEN.finditer(text)]
        findings: list[Detection] = []
        for name in names:
            for key in name_keys(name):
                phrase = tuple(normalize_text(token) for token in _TOKEN.findall(key))
                if len(phrase) < 2:
                    continue
                for index in range(0, len(tokens) - len(phrase) + 1):
                    if tuple(token[0] for token in tokens[index:index + len(phrase)]) == phrase:
                        findings.append(Detection(tokens[index][1], tokens[index + len(phrase) - 1][2],
                                                  "PATIENT_NAME", 0.95, "record_patient_context"))
            # First-name references are accepted only in patient-specific
            # possessive/kinship constructions within that same record.
            first = _TOKEN.search(name)
            if first:
                token = first.group()
                for match in re.finditer(r"(?i)(?<!\w)" + re.escape(token) +
                                         r"(?=\s*(?:['’]s\s+(?:attendant|caregiver|relative|guardian)|\s+(?:didi|bhaiya|behenji|amma|babu|बहनजी|भैया)\s+(?:ka|ki|ke|का|की|के)))", text):
                    findings.append(Detection(match.start(), match.end(), "PATIENT_NAME", 0.91,
                                              "record_patient_role_reference"))
                for match in re.finditer(r"(?i)(?<!\w)" + re.escape(token) +
                                         r"\s+(?:ka|ki|ke)\s+(?:bp|pulse|bukhar|dard|khansi|sugar|ulti)\b", text):
                    findings.append(Detection(match.start(), match.start() + len(token), "PATIENT_NAME",
                                              0.91, "record_patient_clinical_reference"))
        return findings

    def add_sensitive_value(self, category: str, value: str) -> None:
        value = value.strip()
        if not value or len(value) > 180:
            return
        if category in {"PATIENT_NAME", "RELATIVE_NAME"}:
            self.add_name(value)
        self._sensitive_values.setdefault(category, set()).update(name_keys(value))
        self._index_dirty = True

    def add_name(self, value: str, trusted: bool = False) -> None:
        value = value.strip()
        if len(value) < 2 or _MEDICAL_FIELD.search(value):
            return
        # Avoid training the lexicon on strings that look like whole addresses or prose.
        if len(value.split()) > 4 or re.search(r"\d|[@:]", value):
            return
        for key in name_keys(value):
            tokens = key.split()
            if not tokens or len(key) > 80:
                continue
            self._names.add(key)
            if len(tokens) >= 2:
                self._names.add(" ".join((tokens[0], tokens[-1][0])))
                self._names.add(" ".join((tokens[0][0], tokens[-1])))
            # Expand common spelling variants only when the full surrounding
            # name context remains available; no single-token fuzzy matching.
            expanded: list[list[str]] = [tokens]
            for index, token in enumerate(tokens):
                aliases = _NAME_SPELLINGS.get(token)
                if aliases:
                    expanded.extend(tokens[:index] + [alias] + tokens[index + 1:] for alias in aliases)
            for variant in expanded:
                if len(variant) >= 2:
                    self._names.add(" ".join(variant))
            if trusted:
                self._known_names.update(self._names.intersection({key, *name_keys(value)}))
                if len(tokens) >= 2:
                    self._known_names.add(" ".join((tokens[0], tokens[-1][0])))
                    self._known_names.add(" ".join((tokens[0][0], tokens[-1])))
        self._index_dirty = True

    def harvest_text(self, text: str, field_name: str = "") -> None:
        category = field_category(field_name)
        if category:
            self.add_sensitive_value(category, text)
            if category in {"PATIENT_NAME", "RELATIVE_NAME"}:
                self.add_name(text, trusted=True)
        if not is_medical_field(field_name):
            for kind, pattern in _CONTEXT_LABELS:
                for match in pattern.finditer(text):
                    self.add_sensitive_value(kind, match.group(1))
        for rx in (_NAME_LABEL, _RELATION):
            for match in rx.finditer(text):
                if rx is _RELATION and _is_known_case_of_prefix(text, match.start()):
                    continue
                is_name = rx is _NAME_LABEL
                self.add_sensitive_value("PATIENT_NAME" if is_name else "RELATIVE_NAME", match.group(1))
                if is_name:
                    self.add_name(match.group(1), trusted=True)
        for match in _NAME_LABEL_REPORT_OF.finditer(text):
            self.add_sensitive_value("PATIENT_NAME", match.group(1))
            self.add_name(match.group(1), trusted=True)
        for match in _NAME_BEFORE_RELATION.finditer(text):
            self.add_sensitive_value("PATIENT_NAME", match.group(1))
            self.add_name(match.group(1), trusted=True)
        for match in _HINDI_PATIENT_OBJECT.finditer(text):
            self.add_sensitive_value("PATIENT_NAME", match.group(1))
            self.add_name(match.group(1), trusted=True)
        for pattern in (_HINGLISH_PATIENT_NOTE, _NAME_BEFORE_KNOWN_HISTORY):
            for match in pattern.finditer(text):
                self.add_sensitive_value("PATIENT_NAME", match.group(1))
                self.add_name(match.group(1), trusted=True)
        for match in _KINSHIP_SUFFIX.finditer(text):
            self.add_sensitive_value("RELATIVE_NAME", match.group(1))
            self.add_name(match.group(1), trusted=True)
        for pattern in _PERSON_ROLE_NAME:
            for match in pattern.finditer(text):
                self.add_sensitive_value("RELATIVE_NAME", match.group(1))
                self.add_name(match.group(1), trusted=True)
        for rx in (_HONORIFIC_NAME, _NAME_HONORIFIC_SUFFIX, _NAME_AGE):
            for match in rx.finditer(text):
                self.add_sensitive_value("PATIENT_NAME", match.group(1))
                self.add_name(match.group(1), trusted=True)

    def is_known_person(self, value: str) -> bool:
        return bool(self._known_names.intersection(name_keys(value)))

    def find(self, text: str, field_name: str = "", patient_names: tuple[str, ...] = ()) -> list[Detection]:
        if not text:
            return []
        field_cat = field_category(field_name)
        medical_field = is_medical_field(field_name)
        protected = protected_spans(text, field_name)
        findings: list[Detection] = []

        def add(match: re.Match[str], category: str, confidence: float, method: str, group: int = 0) -> None:
            start, end = match.span(group)
            if method == "identity_label":
                segment = text[start:end]
                boundary = re.search(r"(?i)\s+(?:age|gender|sex|dob|date\s+of\s+birth|phone|mobile|address|diagnosis|आयु|उम्र)\s*[:=]", segment)
                if boundary:
                    end = start + boundary.start()
            if start < end:
                findings.append(Detection(start, end, category, confidence, method))

        if field_cat:
            findings.append(Detection(0, len(text), field_cat, 0.99, "structured_field"))
            # Structured sensitive fields are unambiguous; do not expose remnants.
            return findings

        for match in _EMAIL.finditer(text): add(match, "EMAIL", 0.99, "email_pattern")
        for match in _PAN.finditer(text): add(match, "PAN", 0.99, "pan_pattern")
        for match in _ABHA_LABEL.finditer(text): add(match, "ABHA_NUMBER", 0.97, "abha_label", 1)
        for match in _AADHAAR_LABEL.finditer(text): add(match, "AADHAAR", 0.98, "aadhaar_label", 1)
        for match in _GENERIC_ID.finditer(text):
            raw_label = match.group(0)[:match.start(1) - match.start()]
            if re.search(r"(?i)abha", raw_label):
                category = "ABHA_NUMBER"
            elif re.search(r"(?i)insurance|policy|claim", raw_label):
                category = "INSURANCE_ID"
            else:
                category = "MRN"
            add(match, category, 0.96, "identifier_label", 1)
        for match in _FILE_ID.finditer(text):
            findings.append(Detection(match.start(), match.end(), "MRN", 0.88, "structured_id_shape"))
        for match in _PHONE_LABEL.finditer(text):
            span = match.span(1)
            digits = re.sub(r"\D", "", text[span[0]:span[1]])
            if len(digits) >= 10:
                findings.append(Detection(span[0], span[1], "PHONE", 0.96, "phone_label"))
        for match in _PIN_LABEL.finditer(text): add(match, "PIN", 0.98, "pin_label", 1)
        for match in _DOB_LABEL.finditer(text): add(match, "DOB", 0.96, "dob_label", 1)
        for category, pattern in _CONTEXT_LABELS:
            for match in pattern.finditer(text):
                add(match, category, 0.91, "location_or_policy_label", 1)
        for match in _ADDRESS_LABEL.finditer(text): add(match, "ADDRESS", 0.92, "address_label", 1)
        for match in _HOUSE.finditer(text): add(match, "HOUSE", 0.92, "house_label", 1)
        for match in _NAME_LABEL.finditer(text):
            add(match, "PATIENT_NAME", 0.96, "identity_label", 1)
        for match in _NAME_LABEL_REPORT_OF.finditer(text):
            add(match, "PATIENT_NAME", 0.95, "report_subject_context", 1)
        for match in _NAME_BEFORE_RELATION.finditer(text):
            add(match, "PATIENT_NAME", 0.91, "identity_relation_context", 1)
        for match in _HINDI_PATIENT_OBJECT.finditer(text):
            add(match, "PATIENT_NAME", 0.91, "hindi_patient_object_context", 1)
        for match in _HINGLISH_PATIENT_NOTE.finditer(text):
            if re.search(r"(?i)\bdr\.?\s*$", text[max(0, match.start(1) - 8):match.start(1)]):
                continue
            add(match, "PATIENT_NAME", 0.93, "hinglish_patient_note_context", 1)
        for match in _NAME_BEFORE_KNOWN_HISTORY.finditer(text):
            add(match, "PATIENT_NAME", 0.91, "patient_history_context", 1)
        for match in _KINSHIP_SUFFIX.finditer(text):
            add(match, "RELATIVE_NAME", 0.92, "kinship_suffix_context", 1)
        for pattern in (_HONORIFIC_NAME, _NAME_HONORIFIC_SUFFIX, _NAME_AGE):
            for match in pattern.finditer(text):
                add(match, "PATIENT_NAME", 0.84, "honorific_or_demographic_context", 1)
        for match in _RELATION.finditer(text):
            if _is_known_case_of_prefix(text, match.start()):
                continue
            marker = text[match.start():match.start(1)].casefold()
            relative = match.group(1)
            if _MEDICAL_WORDS.search(relative) or protected_spans(relative):
                continue
            if re.search(r"c\s*/\s*o", marker) and not self.is_known_person(relative):
                # C/O is also shorthand for complaint-of. Preserve known clinical
                # phrases above; otherwise require person-like spelling/context.
                words = relative.split()
                is_devanagari = bool(re.search(r"[\u0900-\u097f]", relative))
                is_title_case = any(
                    token[:1].isupper() and not token.isupper() and token[1:].islower()
                    for token in words if token
                )
                if len(words) == 1 and not is_title_case:
                    continue
                if is_devanagari and len(words) == 1 and not self.is_known_person(relative):
                    continue
            add(match, "RELATIVE_NAME", 0.92, "relationship_context", 1)
        for pattern in _PERSON_ROLE_NAME:
            for match in pattern.finditer(text):
                person = match.group(1)
                words = person.split()
                looks_like_name = bool(re.search(r"[\u0900-\u097f]", person)) or any(
                    token[:1].isupper() and not token.isupper() and token[1:].islower()
                    for token in words if token
                )
                if not looks_like_name or normalize_text(person) in _SCHEMA_WORDS:
                    continue
                if not protected_spans(person):
                    add(match, "RELATIVE_NAME", 0.94, "person_role_context", 1)

        # Context-free numeric patterns are bounded by shape and length.
        for match in _ABHA.finditer(text):
            findings.append(Detection(match.start(), match.end(), "ABHA_NUMBER", 0.88, "14_digit_id"))
        for match in _AADHAAR.finditer(text):
            digits = re.sub(r"\D", "", match.group())
            if len(digits) == 12:
                findings.append(Detection(match.start(), match.end(), "AADHAAR", 0.90, "12_digit_id"))
        for match in _PHONE.finditer(text):
            digits = re.sub(r"\D", "", match.group())
            if len(digits) in {10, 11, 12, 13}:
                confidence = 0.98 if re.match(r"\+?91", match.group().strip()) else 0.86
                findings.append(Detection(match.start(), match.end(), "PHONE", confidence, "indian_phone_shape"))
        if re.search(r"(?i)(?:pin|postal|pincode)", text):
            for match in _PIN.finditer(text):
                findings.append(Detection(match.start(), match.end(), "PIN", 0.88, "postal_context"))

        # A patient name learned from a structured identity field can be found in
        # notes/metadata, including an exact cross-script transliteration key.
        if not medical_field:
            findings.extend(self._lexicon_matches(text, require_context=field_name != "__opaque_attachment__"))
            findings.extend(self._lexicon_matches(text, require_context=True, trusted_only=True))
            findings.extend(self._record_patient_matches(text, patient_names))

        # Remove person-like detections that overlap explicit clinical spans.
        explicit_medical_allowed = {
            "email_pattern", "identity_label", "relationship_context", "abha_label",
            "aadhaar_label", "identifier_label", "phone_label", "address_label", "pin_label", "dob_label",
        }
        cleaned: list[Detection] = []
        for item in findings:
            is_person_guess = item.category in {"PATIENT_NAME", "RELATIVE_NAME"}
            overlaps_clinical = any(item.start < end and item.end > start for start, end, _ in protected)
            if is_person_guess and overlaps_clinical:
                known = item.category == "RELATIVE_NAME" and self.is_known_person(text[item.start:item.end])
                if not known and item.method != "identity_label":
                    continue
            if medical_field and item.method not in explicit_medical_allowed:
                continue
            if medical_field and item.method == "relationship_context" and not self.is_known_person(text[item.start:item.end]):
                continue
            cleaned.append(item)

        # Keep the most confident/longest span when detectors overlap.
        chosen: list[Detection] = []
        for item in sorted(cleaned, key=lambda d: (-d.confidence, -(d.end - d.start), d.start, d.category)):
            if any(item.start < prior.end and item.end > prior.start for prior in chosen):
                continue
            chosen.append(item)
        return sorted(chosen, key=lambda d: (d.start, d.end))

    def sanitize(
        self, text: str, field_name: str = "", patient_names: tuple[str, ...] = ()
    ) -> tuple[str, list[Detection]]:
        base64_matches = list(_BASE64.finditer(text))
        if not base64_matches:
            detections = self.find(text, field_name, patient_names)
            result = text
            for item in reversed(detections):
                result = result[:item.start] + f"[{item.category}]" + result[item.end:]
            return result, detections

        pieces: list[str] = []
        detections: list[Detection] = []
        cursor = 0
        for match in base64_matches:
            before = text[cursor:match.start()]
            hits = self.find(before, field_name, patient_names)
            for item in reversed(hits):
                before = before[:item.start] + f"[{item.category}]" + before[item.end:]
            pieces.append(before)
            detections.extend(Detection(item.start + cursor, item.end + cursor, item.category,
                                        item.confidence, item.method) for item in hits)
            token = match.group()
            try:
                decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=False).decode("utf-8", errors="strict")
                printable = sum(char.isprintable() or char.isspace() for char in decoded) / max(1, len(decoded))
                if decoded and printable > 0.9:
                    inner_hits = self.find(decoded, "__opaque_attachment__", patient_names)
                    if inner_hits:
                        cleaned = decoded
                        for item in reversed(inner_hits):
                            cleaned = cleaned[:item.start] + f"[{item.category}]" + cleaned[item.end:]
                        token = base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
                        detections.extend(Detection(match.start(), match.end(), item.category,
                                                    item.confidence, "base64_decoded_" + item.method)
                                          for item in inner_hits)
            except (binascii.Error, UnicodeError, ValueError):
                pass
            pieces.append(token)
            cursor = match.end()
        tail = text[cursor:]
        hits = self.find(tail, field_name, patient_names)
        for item in reversed(hits):
            tail = tail[:item.start] + f"[{item.category}]" + tail[item.end:]
        pieces.append(tail)
        detections.extend(Detection(item.start + cursor, item.end + cursor, item.category,
                                    item.confidence, item.method) for item in hits)
        return "".join(pieces), detections

    def sanitize_scalar(
        self, value: object, field_name: str = "", patient_names: tuple[str, ...] = ()
    ) -> tuple[object, list[Detection]]:
        if isinstance(value, str):
            return self.sanitize(value, field_name, patient_names)
        if isinstance(value, bool) or value is None or not isinstance(value, (int, float)):
            return value, []
        if field_category(field_name):
            detection = Detection(0, 1, field_category(field_name) or "IDENTIFIER", 0.99, "structured_numeric_field")
            return (0.0 if isinstance(value, float) else 0), [detection]
        return value, []

    def sanitize_header_or_key(self, value: str) -> tuple[str, list[Detection]]:
        tokens = [token.casefold() for token in _TOKEN.findall(value)]
        if re.fullmatch(r"(?i)(?:stay[_\W]+duration|hospital[_\W]+stay|length[_\W]+of[_\W]+stay)", value.strip()):
            return value, []
        if 1 <= len(tokens) <= 4 and set(tokens).issubset(_SCHEMA_WORDS):
            return value, []
        if self.is_known_person(value):
            return "[PATIENT_NAME]", [Detection(0, len(value), "PATIENT_NAME", 0.89, "trusted_identity_header")]
        cleaned, hits = self.sanitize(value)
        if hits:
            id_hits = [hit for hit in hits if hit.category in {"MRN", "ABHA_NUMBER", "AADHAAR", "PAN"}]
            if id_hits:
                tail = value[max(hit.end for hit in id_hits):].strip(" _-/,:#")
                if tail and re.fullmatch(r"[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*(?:\s+[A-Z\u0900-\u097f][A-Z\u0900-\u097f.'’\-]*){0,2}", tail, re.I):
                    return "[MRN] [PATIENT_NAME]", hits + [Detection(len(value) - len(tail), len(value), "PATIENT_NAME", 0.88, "identifier_person_header")]
            return cleaned, hits
        if 2 <= len(tokens) <= 4 and not set(tokens).intersection(_SCHEMA_WORDS):
            suspicious = Detection(0, len(value), "PATIENT_NAME", 0.66, "unclassified_header_or_key")
            return "[PATIENT_NAME]", [suspicious]
        return cleaned, []

