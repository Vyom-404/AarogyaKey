"""Unicode and lightweight Devanagari normalization for detection/matching."""

from __future__ import annotations

import re
import unicodedata

_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")
_CONSONANTS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "ng",
    "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "ny",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n",
    "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m",
    "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
    "ष": "sh", "स": "s", "ह": "h", "क़": "q", "ख़": "kh",
    "ग़": "gh", "ज़": "z", "ड़": "r", "ढ़": "rh", "फ़": "f",
}
_VOWELS = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu",
           "ऋ": "ri", "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au"}
_MATRAS = {"ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri",
           "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "ॅ": "e", "ॉ": "o"}


def normalize_text(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).translate(_DIGITS).casefold()
    value = value.replace("़", "")
    return " ".join(value.split())


def transliterate_devanagari(value: str) -> str:
    """Approximate common Hindi names in Latin script; used only as a match aid."""
    chars = list(unicodedata.normalize("NFKC", value))
    output: list[str] = []
    i = 0
    while i < len(chars):
        char = chars[i]
        if char in _CONSONANTS:
            stem = _CONSONANTS[char]
            if i + 1 < len(chars) and chars[i + 1] == "़":
                stem = _CONSONANTS.get(char + "़", stem)
                i += 1
            if i + 1 < len(chars) and chars[i + 1] in _MATRAS:
                output.append(stem + _MATRAS[chars[i + 1]])
                i += 2
                continue
            if i + 1 < len(chars) and chars[i + 1] == "्":
                output.append(stem)
                i += 2
                continue
            output.append(stem + "a")
        elif char in _VOWELS:
            output.append(_VOWELS[char])
        elif char in ("ं", "ँ"):
            output.append("n")
        elif char == "ः":
            output.append("h")
        elif char in ("्", "़") or char == "\u200d":
            pass
        else:
            output.append(char)
        i += 1
    latin = "".join(output).casefold()
    latin = re.sub(r"([a-z])a\b", r"\1", latin)
    return " ".join(latin.split())


def name_keys(value: str) -> set[str]:
    normalized = normalize_text(value)
    normalized = re.sub(r"^[^\w\u0900-\u097f]+|[^\w\u0900-\u097f]+$", "", normalized, flags=re.UNICODE)
    variants = {normalized} if normalized else set()
    if normalized:
        variants.add(normalized.replace("aa", "a").replace("ii", "i").replace("uu", "u"))
    if any("\u0900" <= char <= "\u097f" for char in value):
        latin = transliterate_devanagari(value)
        latin = normalize_text(latin)
        if latin:
            variants.add(latin)
            variants.add(latin.replace("aa", "a").replace("ii", "i").replace("uu", "u"))
    return variants

