"""Protected clinical spans that generic PII rules must not redact."""

from __future__ import annotations

import re

# Values and units/frequencies are protected as a whole. These patterns do not
# alter their text; they only block overlapping name/identifier guesses.
_CLINICAL_PATTERNS = [
    re.compile(r"(?i)\b[A-Z][A-Z0-9-]*(?:\s+[A-Z][A-Z0-9-]*){0,2}\s+\d+(?:\.\d+)?\s*(?:mg|mcg|µg|g|kg|ml|mL|mmol/L)\b"),
    re.compile(r"(?i)\b(?:Dolo|Crocin|Calpol|Paracetamol|Acetaminophen|ORS|Cetirizine|Azithromycin|Amoxicillin)\s+\d{2,4}\b(?:\s+(?:OD|BD|BID|TDS|TID|QID))?(?:\s*(?:x|for)\s*\d+\s*days?)?"),
    re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg|mcg|µg|g|kg|ml|mL|mmol/L|mg/dL|g/dL|mmHg|°[CF]|%)\b"),
    re.compile(r"(?i)\b\d+\s*[-–/]\s*\d+\s*[-–/]\s*\d+(?:\s*(?:x|×)\s*\d+\s*(?:days?|d|weeks?))?\b"),
    re.compile(r"(?i)\b(?:OD|BD|BID|TDS|TID|QID|HS|SOS|stat)\b(?:\s*(?:x|for)\s*\d+\s*(?:days?|d|weeks?))?"),
    re.compile(r"(?i)\b(?:BP|HR|PR|RR|SpO2|SPO₂|HbA1c|Hb|WBC|RBC|ECG|BMI|Temp(?:erature)?)\s*[:=]?\s*\d+(?:[./:]\d+)*(?:\s*[°%A-Za-zµ/]+)?"),
    re.compile(r"(?i)\b(?:Dr|Doctor|डॉ|चिकित्सक)\.?\s*[\w.\-\u0900-\u097f]+(?:\s+[\w.\-\u0900-\u097f]+){0,3}"),
    re.compile(r"(?i)(?:doctor|physician|consultant|surgeon|nurse|clinician|डॉक्टर|चिकित्सक)\s*[:=-]\s*[^,;|\n]+"),
    re.compile(r"(?i)(?:ward|department|unit|ward\s*no)\s*[:=-]\s*[^,;|\n]+"),
    re.compile(r"(?i)\bward\s*(?:no\.?\s*)?[A-Z0-9][A-Z0-9-]*\b"),
    re.compile(r"(?i)(?:history|medical\s*history|hx|h/o)\s*[:=-]\s*[^,;|\n]+"),
    re.compile(r"(?i)(?:diagnosis|diagnosis\s*code|dx|icd(?:-\d+)?)\s*[:=-]\s*[^,;|\n]+"),
    re.compile(r"(?i)(?:procedure|surgery|treatment|procedure\s*performed)\s*[:=-]\s*[^,;|\n]+"),
]

_CLINICAL_TERMS = {
    "fever", "bukhar", "बुखार", "cough", "खांसी", "khansi", "dengue", "डेंगू",
    "malaria", "मलेरिया", "diabetes", "मधुमेह", "hypertension", "उच्च रक्तचाप",
    "asthma", "अस्थमा", "pneumonia", "निमोनिया", "parkinson's disease",
    "addison's disease", "fracture", "infection", "anemia", "anaemia", "migraine",
    "tuberculosis", "tb", "typhoid", "jaundice", "पीलीया", "pain", "दर्द",
    "abdominal pain", "chest pain", "headache", "nausea", "vomiting", "loose motion",
    "loose stools", "diarrhea", "diarrhoea", "weakness", "breathlessness", "dyspnea",
    "rash", "swelling", "giddiness", "dizziness", "dehydration", "constipation",
    "palpitations", "body ache", "body pain", "joint pain", "back pain", "sore throat",
    "runny nose", "cold", "chills", "fatigue", "loss of appetite", "खांसी", "उल्टी",
    "मतली", "सिरदर्द", "कमजोरी", "सांस फूलना", "दस्त", "चकत्ते", "सूजन", "चक्कर",
    "hodgkin lymphoma", "hodgkin's lymphoma", "graves disease", "graves' disease",
    "crohn disease", "crohn's disease", "hashimoto disease", "hashimoto's disease",
    "alzheimer disease", "alzheimer's disease", "addison disease", "addison's disease",
    "bell's palsy", "bell palsy", "chronic kidney disease", "ckd", "type 2 diabetes mellitus",
    "surgery", "medicine", "pediatrics", "paediatrics", "cardiology", "neurology",
    "oncology", "orthopedics", "orthopaedics", "obstetrics", "gynecology", "gynaecology",
    "emergency", "intensive care", "icu", "general medicine",
}
_TERM_RX = re.compile(
    r"(?i)(?<![\w])(?:" + "|".join(re.escape(term) for term in sorted(_CLINICAL_TERMS, key=len, reverse=True)) + r")(?![\w])"
)


def protected_spans(text: str, field_name: str = "") -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    field = field_name.casefold()
    if any(word in field for word in ("doctor", "physician", "provider", "clinician", "medicine", "drug", "dose", "frequency", "diagnosis", "disease", "symptom", "complaint", "lab", "vital", "procedure", "treatment")):
        if text:
            spans.append((0, len(text), "clinical_field"))
            return spans
    for pattern in _CLINICAL_PATTERNS:
        spans.extend((match.start(), match.end(), "clinical_pattern") for match in pattern.finditer(text))
    spans.extend((match.start(), match.end(), "clinical_term") for match in _TERM_RX.finditer(text))
    # A diagnosis/history label protects its immediate value through a delimiter.
    for match in re.finditer(r"(?i)(?:diagnosis(?:\s+code)?|icd(?:-\d+)?|assessment|history|clinical\s+impression|क्लिनिकल इम्प्रेशन|निदान)\s*[:=-]\s*([^,;|\n]+)", text):
        start, end = match.span(1)
        spans.append((start, end, "clinical_context"))
    return spans

