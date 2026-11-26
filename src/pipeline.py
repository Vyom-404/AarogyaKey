"""Deterministic privacy transformation, linkage, and contract output pipeline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import re
import resource
import secrets as secure_random
import stat
import sys
import time
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from src.config import load_policy
from src.detection import Detection, PIIDetector
from src.detection.detector import field_category, is_medical_field
from src.linkage import PatientResolver, Pseudonymizer
from src.linkage.extractor import extract_records
from src.linkage.models import RecordIdentity
from src.privacy import build_privacy_actions, collect_privacy_records, equivalence_summary
from src.privacy.extractor import PrivacyAction, PrivacyRecord
from src.security.filesystem import hash_regular_file, read_regular_file
from src.security.safe_logging import log_event

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "policy.yaml"
SUPPORTED = {".csv", ".tsv", ".json", ".txt"}
LOGGER = logging.getLogger("raksha.security")


class UnsafeInput(ValueError):
    """Input could not be safely processed for the current phase."""


def decode_bytes(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="strict")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="strict")
    for encoding in ("utf-8", "cp1252"):
        try:
            return raw.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            pass
    raise UnsafeInput("undecodable_text")


def discover(root: Path) -> list[Path]:
    """Return regular files in stable order, without traversing symlink dirs."""
    found: list[Path] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        linked_dirs = [base / d for d in dirs if (base / d).is_symlink()]
        found.extend(linked_dirs)
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        found.extend(base / name for name in names)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def _json_depth(value: Any, maximum: int) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise UnsafeInput("max_json_depth_exceeded")
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)


def _json_records(data: Any, output_file: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(data, dict) and data.get("resourceType") == "Bundle":
        records.append({"file": output_file, "loc": "doc", "patient": None})
        return records
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                records.extend(
                    {"file": output_file, "loc": f"/{escaped}/{index}", "patient": None}
                    for index in range(len(value))
                )
    if not records:
        records.append({"file": output_file, "loc": "doc", "patient": None})
    return records


def _string_leaves(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [text for key, value in node.items() if key.casefold() in {"name", "given", "family", "text", "first", "last", "firstname", "lastname", "middle", "local", "display"} for text in _string_leaves(value)]
    if isinstance(node, list):
        return [text for value in node for text in _string_leaves(value)]
    return []


def _csv_field_context(header: str, rel: str, value: str = "") -> str:
    """Use directory semantics to disambiguate demographic locality columns."""
    pieces = {piece.casefold().replace("-", "_") for piece in Path(rel).parts}
    field = header.casefold().strip().replace("-", "_").replace(" ", "_")
    demographic_path = pieces.intersection(
        {"registration", "registrations", "patient", "patients", "demographic", "demographics"}
    )
    if field == "village" and demographic_path:
        return "village"
    if field == "city" and demographic_path and re.search(r"(?i)(?:dih|nagar|khurd)$", value.strip()):
        return "village"
    return header


def _harvest_json(node: Any, detector: PIIDetector, context: str = "") -> None:
    if isinstance(node, dict):
        local_context = context
        resource_type = node.get("resourceType")
        if isinstance(resource_type, str) and resource_type.casefold() in {
            "organization", "practitioner", "practitionerrole", "location", "healthcareservice",
            "condition", "observation", "procedure", "medication", "medicationrequest",
            "diagnosticreport", "encounter", "servicerequest", "specimen", "careteam",
        }:
            local_context = "__clinical_resource__" + resource_type
        for key, value in node.items():
            category = field_category(str(key))
            identity_context = category in {"PATIENT_NAME", "RELATIVE_NAME"} and not is_medical_field(local_context)
            if identity_context:
                combined = " ".join(_string_leaves(value))
                if combined:
                    detector.add_name(combined, trusted=True)
            if isinstance(value, str):
                harvest_context = local_context if is_medical_field(local_context) and str(key).casefold() in {"name", "display", "text"} else str(key) or local_context
                detector.harvest_text(value, harvest_context)
                if identity_context:
                    detector.add_name(value)
            else:
                child_context = local_context + "_name" if is_medical_field(local_context) and str(key).casefold() in {"name", "display", "text"} else str(key) or local_context
                _harvest_json(value, detector, child_context)
    elif isinstance(node, list):
        for item in node:
            _harvest_json(item, detector, context)
    elif isinstance(node, str):
        detector.harvest_text(node, context)


def harvest_input_names(input_dir: Path, max_bytes: int, max_json_depth: int) -> PIIDetector:
    """Build a conservative dataset-local name list from labeled identity fields."""
    detector = PIIDetector()
    for path in discover(input_dir):
        if path.is_symlink() or path.suffix.lower() not in SUPPORTED:
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = decode_bytes(read_regular_file(path, max_bytes))
            if path.suffix.lower() in {".csv", ".tsv"}:
                delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
                rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True))
                if rows:
                    headers = rows[0]
                    for row in rows[1:]:
                        for index, value in enumerate(row):
                            header = _csv_field_context(headers[index], path.relative_to(input_dir).as_posix(), value) if index < len(headers) else ""
                            detector.harvest_text(value, header)
            elif path.suffix.lower() == ".json":
                data = json.loads(text)
                _json_depth(data, max_json_depth)
                _harvest_json(data, detector)
            else:
                detector.harvest_text(text)
        except (OSError, UnicodeError, ValueError, csv.Error, RecursionError):
            continue
    return detector


def _patient_names_in_record(value: dict[str, Any], context: str = "") -> tuple[str, ...]:
    names: list[str] = []
    resource_type = value.get("resourceType")
    for key, child in value.items():
        normalized_key = str(key).casefold().replace("-", "_")
        if normalized_key in {"patient", "subject", "beneficiary", "patientreference", "patient_reference"}:
            names.extend(_string_leaves(child))
        elif normalized_key in {"patient_name", "patientname", "subject_name", "beneficiary_name", "patient_full_name"}:
            names.extend(_string_leaves(child) if not isinstance(child, str) else [child])
        elif context.casefold() == "patient" and normalized_key == "name":
            names.extend(_string_leaves(child) if not isinstance(child, str) else [child])
        elif isinstance(resource_type, str) and resource_type.casefold() == "patient" and normalized_key == "name":
            names.extend(_string_leaves(child))
    # Keep only multi-token name candidates; identifiers and opaque references
    # do not qualify as record-local person names.
    return tuple(dict.fromkeys(name.strip() for name in names if len(name.split()) >= 2 and "/" not in name and "@" not in name))


def _clean_json(
    value: Any, detector: PIIDetector, context: str = "", patient_names: tuple[str, ...] = ()
) -> tuple[Any, list[Detection]]:
    detections: list[Detection] = []
    if isinstance(value, dict):
        local_context = context
        resource_type = value.get("resourceType")
        if isinstance(resource_type, str) and resource_type.casefold() in {
            "organization", "practitioner", "practitionerrole", "location", "healthcareservice",
            "condition", "observation", "procedure", "medication", "medicationrequest",
            "diagnosticreport", "encounter", "servicerequest", "specimen", "careteam",
        }:
            local_context = "__clinical_resource__" + resource_type
        local_patient_names = tuple(dict.fromkeys(patient_names + _patient_names_in_record(value, local_context)))
        extension_category = field_category(str(value.get("url", "")))
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            new_key, key_hits = detector.sanitize_header_or_key(key_text)
            detections.extend(key_hits)
            normalized_key = key_text.casefold().replace("-", "_")
            nested_context = key_text
            if is_medical_field(local_context):
                nested_context = local_context
                if key_text.casefold() in {"subject", "patient", "patientreference", "beneficiary"}:
                    nested_context = "patient"
                elif key_text.casefold() == "identifier":
                    nested_context = "identifier"
            elif local_context.casefold() == "patient":
                if key_text.casefold() in {"display", "name", "given", "family", "text"}:
                    nested_context = "patient_name"
                elif key_text.casefold() in {"reference", "identifier", "id", "value"}:
                    nested_context = "patient_id"
            elif normalized_key in {"patient", "subject", "beneficiary", "patientreference", "patient_reference"}:
                nested_context = "patient"
            elif normalized_key in {"relative", "guardian", "next_of_kin", "nextofkin", "emergency_contact"}:
                nested_context = "relative"
            elif normalized_key in {
                "author", "created_by", "updated_by", "uploaded_by", "raised_by",
                "reported_by", "entered_by", "submitted_by", "sender", "recipient", "contact_person",
            }:
                nested_context = "person_name"
            elif normalized_key in {"meta", "metadata", "_export_meta", "audit", "provenance"}:
                nested_context = "metadata"
            elif field_category(local_context) == "ADDRESS" and normalized_key in {
                "line", "street", "house", "house_number", "flat", "premise", "district", "city", "town",
                "village", "locality", "postalcode", "postal_code", "zip", "zipcode", "pin", "pincode",
            }:
                nested_context = "address_" + normalized_key
            elif local_context.casefold() == "relative" and normalized_key in {"name", "display", "given", "family", "text"}:
                nested_context = "relative_name"
            elif local_context.casefold() == "person_name" and normalized_key in {"name", "display", "given", "family", "text"}:
                nested_context = "patient_name"
            elif local_context.casefold() == "metadata":
                # Preserve the concrete key alias so structured metadata fields
                # such as source_path receive their category rules.
                nested_context = key_text
            if extension_category and normalized_key.startswith("value"):
                nested_context = extension_category
            if local_patient_names and normalized_key in {"note", "notes", "comment", "comments", "narrative", "remarks"}:
                nested_context = "patient_notes"
            if field_category(local_context) and key_text.casefold() in {"value", "number", "identifier", "id"}:
                nested_context = local_context
            if is_medical_field(local_context) and key_text.casefold() in {"name", "display", "text", "given", "family"}:
                nested_context = local_context + "_name"
            if field_category(local_context) == "PATIENT_NAME" and key_text.casefold() in {"given", "family", "text", "first", "last", "firstname", "lastname", "middle", "local", "display"}:
                nested_context = "patient_name"
            new_child, child_hits = _clean_json(child, detector, nested_context, local_patient_names)
            detections.extend(child_hits)
            cleaned[str(new_key)] = new_child
        return cleaned, detections
    if isinstance(value, list):
        cleaned_list = []
        for child in value:
            new_child, hits = _clean_json(child, detector, context, patient_names)
            cleaned_list.append(new_child)
            detections.extend(hits)
        return cleaned_list, detections
    cleaned_value, hits = detector.sanitize_scalar(value, context, patient_names)
    return cleaned_value, hits


def transform_file(
    path: Path, rel: str, max_bytes: int, max_json_depth: int, detector: PIIDetector | None = None,
    identity_records: list[RecordIdentity] | None = None,
    pseudonyms: dict[tuple[str, str], str] | None = None,
    privacy_actions: dict[tuple[str, str], list[PrivacyAction]] | None = None,
    raw_data: bytes | None = None,
) -> tuple[str, list[dict[str, Any]], int, list[Detection], list[PrivacyAction]]:
    """Decode and serialize a supported file; return text, locators, record count."""
    if path.is_symlink():
        raise UnsafeInput("symlink_input")
    try:
        size = path.stat().st_size
    except OSError:
        raise UnsafeInput("file_stat_error") from None
    if size > max_bytes:
        raise UnsafeInput("max_file_size_exceeded")
    detector = detector or PIIDetector()
    identity_records = identity_records or []
    pseudonyms = pseudonyms or {}
    privacy_actions = privacy_actions or {}
    identities = {record.loc: record for record in identity_records}
    applied_actions: list[PrivacyAction] = []
    try:
        raw = raw_data if raw_data is not None else read_regular_file(path, max_bytes)
    except ValueError as exc:
        raise UnsafeInput(str(exc)) from None
    if not raw.strip():
        raise UnsafeInput("empty_file")
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED:
        raise UnsafeInput("unsupported_format")
    text = decode_bytes(raw)
    output_file = f"sanitized/{rel}"

    if suffix in (".csv", ".tsv"):
        # Reject obvious mislabeled JSON rather than exporting it as a CSV cell.
        if text.lstrip().startswith(("{", "[")):
            raise UnsafeInput("format_mismatch")
        delimiter = "\t" if suffix == ".tsv" else ","
        try:
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True))
        except csv.Error:
            raise UnsafeInput("malformed_csv") from None
        if not rows:
            raise UnsafeInput("empty_file")
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, delimiter=delimiter, lineterminator="\n")
        detections: list[Detection] = []
        safe_header = []
        for cell in rows[0]:
            value, hits = detector.sanitize_header_or_key(cell)
            safe_header.append(value)
            detections.extend(hits)
        writer.writerow(safe_header)
        table_records = []
        for row_index, row in enumerate(rows[1:]):
            loc = f"row:{row_index}"
            row_actions = privacy_actions.get(loc, [])
            for action in row_actions:
                if action.stage == "before" and len(action.path) == 1 and isinstance(action.path[0], int):
                    if action.path[0] < len(row):
                        row[action.path[0]] = action.replacement
            clean_row = []
            for index, cell in enumerate(row):
                context = _csv_field_context(rows[0][index], rel, cell) if index < len(rows[0]) else ""
                value, hits = detector.sanitize_scalar(cell, context)
                identity = identities.get(f"row:{row_index}")
                patient = pseudonyms.get((identity.file, identity.loc)) if identity else None
                if (patient and identity and identity.carrier and identity.carrier.path == (index,)):
                    value = patient
                for action in row_actions:
                    if action.path == (index,):
                        value = action.replacement
                        applied_actions.append(action)
                clean_row.append(value)
                detections.extend(hits)
            writer.writerow(clean_row)
            identity = identities.get(loc)
            patient = pseudonyms.get((identity.file, identity.loc)) if identity else None
            table_records.append({"file": output_file, "loc": loc, "patient": patient})
        return stream.getvalue(), table_records, len(table_records), detections, applied_actions

    if suffix == ".json":
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            raise UnsafeInput("malformed_json") from None
        _json_depth(data, max_json_depth)
        if isinstance(data, dict) and data.get("resourceType") == "Bundle":
            if not isinstance(data.get("type"), str) or not isinstance(data.get("entry", []), list):
                raise UnsafeInput("invalid_fhir_bundle")
        json_actions = [action for group in privacy_actions.values() for action in group]
        for action in json_actions:
            if action.stage == "before" and action.path and _set_path(data, action.path, action.replacement):
                applied_actions.append(action)
        records = _json_records(data, output_file)
        clean_data, detections = _clean_json(data, detector)
        for record in records:
            identity = identities.get(record["loc"])
            if not identity:
                continue
            patient = pseudonyms.get((identity.file, identity.loc))
            record["patient"] = patient
            if patient and identity.carrier and identity.carrier.path:
                if not _set_path(clean_data, identity.carrier.path, patient):
                    # If a structural path cannot be safely replaced, keep the
                    # pseudonym in records.jsonl and insert it at document level.
                    if isinstance(clean_data, dict):
                        clean_data.setdefault("patient_pseudonym", patient)
            for action in privacy_actions.get(record["loc"], []):
                if (action.stage == "after" or action.marker) and action.path:
                    if _set_path(clean_data, action.path, action.replacement) and action not in applied_actions:
                        applied_actions.append(action)
        return json.dumps(clean_data, ensure_ascii=False, indent=2) + "\n", records, len(records), detections, applied_actions

    identity = identities.get("doc")
    patient = pseudonyms.get((identity.file, identity.loc)) if identity else None
    records = [{"file": output_file, "loc": "doc", "patient": patient}]
    doc_actions = privacy_actions.get("doc", [])
    text = _apply_text_edits(text, doc_actions, "before")
    clean_text, detections = detector.sanitize(text)
    clean_text = _overlay_markers(clean_text, doc_actions)
    applied_actions.extend(doc_actions)
    if patient:
        marker = "[PATIENT_NAME]"
        if marker in clean_text:
            clean_text = clean_text.replace(marker, patient, 1)
        else:
            clean_text = clean_text.rstrip() + f"\nPatient ID: {patient}\n"
    return clean_text, records, 1, detections, applied_actions


def sanitized_relative_path(rel: str, content_hash: str, detector: PIIDetector) -> str:
    """Replace PII-bearing path components without logging their original text."""
    parts = rel.split("/")
    safe_parts: list[str] = []
    for index, part in enumerate(parts):
        suffix = Path(part).suffix if index == len(parts) - 1 else ""
        stem = part[:-len(suffix)] if suffix else part
        date_pattern = re.compile(r"(?<!\d)(?:\d{4}[-_.]\d{1,2}[-_.]\d{1,2}|\d{1,2}[-_.]\d{1,2}[-_.]\d{4})(?!\d)")
        stem = date_pattern.sub("[DATE]", stem)
        if detector.find(stem, "filename"):
            prefix = "file" if index == len(parts) - 1 else "folder"
            safe_parts.append(f"{prefix}_{content_hash[:12]}{suffix}")
        else:
            safe_parts.append(stem + suffix)
    return "/".join(safe_parts)


def peak_rss_mb() -> float:
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(value / (1024 if sys.platform != "darwin" else 1024 * 1024), 1)
    except (AttributeError, OSError):
        return 0.0


def _set_path(root: Any, path: tuple[str | int, ...], value: Any) -> bool:
    if not path:
        return False
    target = root
    try:
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        return True
    except (KeyError, IndexError, TypeError):
        return False


def _apply_text_edits(text: str, actions: list[PrivacyAction], stage: str) -> str:
    edits = [action for action in actions if action.stage == stage and action.span]
    for action in sorted(edits, key=lambda item: item.span[0], reverse=True):
        start, end = action.span
        if 0 <= start <= end <= len(text):
            text = text[:start] + action.replacement + text[end:]
    return text


def _overlay_markers(text: str, actions: list[PrivacyAction]) -> str:
    for action in sorted((item for item in actions if item.marker), key=lambda item: (item.marker, -item.marker_index)):
        occurrences = [match.span() for match in re.finditer(re.escape(action.marker), text)]
        if action.marker_index < len(occurrences):
            start, end = occurrences[action.marker_index]
            text = text[:start] + action.replacement + text[end:]
    return text


def _report_entry(path: Path, raw: bytes | None, status: str, output: str | None,
                  reason: str | None = None, digest: str | None = None) -> dict:
    # A read failure still receives an explicit report entry. Empty-byte hash is
    # a sentinel because the input bytes could not be read for hashing.
    digest = digest or hashlib.sha256(raw if raw is not None else b"").hexdigest()
    entry = {"input_sha256": digest, "output": output, "status": status}
    if reason:
        entry["reason"] = reason
    return entry


def _private_directory(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
            except OSError:
                raise OSError("private_directory_unavailable") from None
            info = current.lstat()
        except OSError:
            raise OSError("private_directory_unavailable") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise OSError("private_directory_unavailable") from None
    os.chmod(path, 0o700)


def _safe_output_path(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise UnsafeInput("unsafe_output_path")
    return root.joinpath(*candidate.parts)


def _private_write(path: Path, text: str) -> None:
    """Write through a private sibling and atomically publish, cleaning on error."""
    _private_directory(path.parent)
    temporary = path.with_name("." + path.name + "." + secure_random.token_hex(8) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _validate_output_tree(output_dir: Path, secret: str) -> None:
    """Reject symlinks and raw-secret artifacts before returning success."""
    secret_bytes = secret.encode("utf-8")
    if stat.S_IMODE(output_dir.lstat().st_mode) & 0o077:
        raise OSError("output_permissions_unsafe") from None
    for current, dirs, names in os.walk(output_dir, followlinks=False):
        base = Path(current)
        for name in list(dirs) + names:
            artifact = base / name
            try:
                info = artifact.lstat()
            except OSError:
                raise OSError("output_scan_failed") from None
            if stat.S_ISLNK(info.st_mode):
                raise OSError("output_symlink_detected") from None
            if secret and secret in name:
                raise OSError("output_secret_detected") from None
            if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o077:
                raise OSError("output_permissions_unsafe") from None
        dirs[:] = sorted(dirs)
        for name in sorted(names):
            artifact = base / name
            if not stat.S_ISREG(artifact.lstat().st_mode):
                raise OSError("output_unsafe_artifact") from None
            if name.endswith(".tmp") or stat.S_IMODE(artifact.lstat().st_mode) & 0o077:
                raise OSError("output_artifact_unsafe") from None
            with artifact.open("rb") as stream:
                overlap = b""
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    scan = overlap + chunk
                    if secret_bytes and secret_bytes in scan:
                        raise OSError("output_secret_detected") from None
                    overlap = scan[-max(0, len(secret_bytes) - 1):] if secret_bytes else b""


def run_pipeline(input_dir: Path, output_dir: Path, secret: str, policy: dict | None = None) -> dict:
    from src.security.secret_manager import validate_secret

    validate_secret(secret)
    if input_dir.is_symlink():
        raise ValueError("input_path_unsafe") from None
    input_dir = input_dir.resolve(strict=True)
    if not input_dir.is_dir():
        raise ValueError("input_path_must_be_directory")
    requested_output = output_dir.expanduser().absolute()
    if requested_output.is_symlink():
        raise ValueError("output_path_unsafe") from None
    output_dir = requested_output.resolve()
    if output_dir == input_dir or input_dir in output_dir.parents or output_dir in input_dir.parents:
        raise ValueError("output_must_be_outside_input")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output_directory_must_be_empty")

    rules = policy or {}
    max_bytes = int(rules.get("max_file_bytes", 50 * 1024 * 1024))
    max_depth = int(rules.get("max_json_depth", 100))
    detector = harvest_input_names(input_dir, max_bytes, max_depth)
    identity_records = extract_records(input_dir, detector, max_bytes)
    minimum_confidence = float(rules.get("linkage_min_confidence", 0.92))
    linkage = PatientResolver(minimum_confidence=minimum_confidence).resolve(
        identity_records, Pseudonymizer(secret)
    )
    privacy_records = collect_privacy_records(input_dir, max_bytes)
    privacy_action_index = build_privacy_actions(privacy_records, linkage.pseudonyms, secret, rules)
    privacy_actions_by_file: dict[str, dict[str, list[PrivacyAction]]] = {}
    for (privacy_file, privacy_loc), actions in privacy_action_index.items():
        privacy_actions_by_file.setdefault(privacy_file, {})[privacy_loc] = actions
    identities_by_file: dict[str, list[RecordIdentity]] = {}
    for identity in identity_records:
        identities_by_file.setdefault(identity.file, []).append(identity)
    started = time.monotonic()
    files_report: list[dict] = []
    records: list[dict[str, Any]] = []
    entity_counts: dict[str, int] = {}
    generalized_records: set[tuple[str, str]] = set()
    suppressed_records: set[tuple[str, str]] = set()
    privacy_action_counts: dict[str, int] = {}
    _private_directory(output_dir)
    sanitized_dir = output_dir / "sanitized"
    _private_directory(sanitized_dir)

    for path in discover(input_dir):
        rel = path.relative_to(input_dir).as_posix()
        raw: bytes | None = None
        reported_digest: str | None = None
        try:
            if path.is_symlink():
                raw = os.readlink(path).encode("utf-8", errors="replace")
                try:
                    target = path.resolve(strict=True)
                    if target.is_file():
                        # Hash only for organizer accounting; never parse or export the referent.
                        reported_digest = hash_regular_file(target)
                except (OSError, ValueError):
                    reported_digest = None
                raise UnsafeInput("symlink_input")
            try:
                raw = read_regular_file(path, max_bytes)
            except ValueError as exc:
                if path.is_symlink():
                    raw = os.readlink(path).encode("utf-8", errors="replace")
                    raise UnsafeInput("symlink_input") from None
                raise UnsafeInput(str(exc)) from None
            content_hash = hashlib.sha256(raw).hexdigest()
            output_rel = sanitized_relative_path(rel, content_hash, detector)
            result, file_records, _, hits, applied_actions = transform_file(
                path, output_rel, max_bytes, max_depth, detector,
                identities_by_file.get(rel, []), linkage.pseudonyms,
                privacy_actions_by_file.get(rel, {}),
                raw,
            )
            destination = _safe_output_path(sanitized_dir, output_rel)
            _private_write(destination, result)
            files_report.append(_report_entry(path, raw, "sanitized", f"sanitized/{output_rel}"))
            log_event(LOGGER, "file_processed", file_sha256=content_hash, status="sanitized")
            records.extend(file_records)
            for action in applied_actions:
                ref = (action.file, action.loc)
                if action.action.startswith(("generalized", "shifted")):
                    generalized_records.add(ref)
                if action.action.startswith("suppressed"):
                    suppressed_records.add(ref)
                privacy_action_counts[action.action] = privacy_action_counts.get(action.action, 0) + 1
            for hit in hits:
                entity_counts[hit.category] = entity_counts.get(hit.category, 0) + 1
        except (OSError, UnsafeInput, UnicodeError, RecursionError, csv.Error, ValueError) as exc:
            reason = str(exc) if isinstance(exc, UnsafeInput) else "read_or_processing_error"
            digest = reported_digest or (hashlib.sha256(raw).hexdigest() if raw is not None else None)
            if digest is None and not path.is_symlink():
                try:
                    digest = hash_regular_file(path)
                except (OSError, ValueError):
                    digest = None
            files_report.append(_report_entry(path, raw, "quarantined", None, reason, digest))
            log_event(LOGGER, "file_processed", file_sha256=digest or hashlib.sha256(b"").hexdigest(),
                      status="quarantined", reason=reason)

    records.sort(key=lambda item: (item["file"], item["loc"]))
    _private_write(output_dir / "records.jsonl",
                   "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records))
    sanitized_count = sum(entry["status"] == "sanitized" for entry in files_report)
    privacy_after_records = collect_privacy_records(sanitized_dir, max_bytes)
    risk_summary = equivalence_summary(privacy_records, privacy_after_records, rules)
    report = {
        "schema": "raksha-report/1",
        "files": files_report,
        "counts": {
            "files_total": len(files_report),
            "files_sanitized": sanitized_count,
            "files_quarantined": len(files_report) - sanitized_count,
            "records_processed": len(records),
            "identifiers_detected": sum(entity_counts.values()),
            "records_linked": sum(record["patient"] is not None for record in records),
            "records_generalized": len(generalized_records),
            "records_suppressed": len(suppressed_records),
            "records_quarantined": 0,
        },
        "entities": dict(sorted(entity_counts.items())),
        "privacy": {"actions": dict(sorted(privacy_action_counts.items())), "risk": risk_summary},
        "timing": {"seconds": round(time.monotonic() - started, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    _private_write(output_dir / "report.json", json.dumps(report, indent=2) + "\n")
    _validate_output_tree(output_dir, secret)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Secret Wards privacy firewall baseline")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    secret = os.environ.get("RAKSHA_SECRET", "")
    if not secret:
        print("error: RAKSHA_SECRET is required", file=sys.stderr)
        return 2
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
    try:
        policy = load_policy(DEFAULT_POLICY)
        report = run_pipeline(Path(args.input), Path(args.output), secret, policy)
    except (OSError, ValueError):
        # Exception text can contain a source path, so only emit a fixed category.
        print("error: processing_failed", file=sys.stderr)
        return 2
    counts = report["counts"]
    print(
        f"files {counts['files_total']} sanitized {counts['files_sanitized']} "
        f"quarantined {counts['files_quarantined']} records {counts['records_processed']}"
    )
    return 0

