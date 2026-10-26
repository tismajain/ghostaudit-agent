"""Build a source-hashed normalized cache for the fixed participant evidence set."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from src.ingest import load

CACHE_VERSION = "transport-quotes-v2"


def _optional_pdf_deps() -> None:
    """Allow an explicitly configured optional dependency directory."""
    configured = os.environ.get("GHOST_PDF_DEPS")
    if configured:
        local = Path(configured).expanduser().resolve()
        if local.is_dir() and str(local) not in sys.path:
            sys.path.insert(0, str(local))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _walk_identifiers(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and key.lower() in {
                "user_id", "subject_reference", "customer_reference", "email", "phone",
                "email_hash", "name", "full_name", "requester_email", "requester_phone",
                "owner_email", "owner_phone", "matched_value", "correlation_key",
            }:
                if item:
                    found.add(item)
            found.update(_walk_identifiers(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_walk_identifiers(item))
    return found


def _ocr_image(image_path: Path) -> tuple[str, str]:
    executable = shutil.which("tesseract")
    if not executable:
        return "", "Tesseract OCR is not installed."
    result = subprocess.run([executable, str(image_path), "stdout"], capture_output=True,
                            text=True, timeout=60, check=False)
    if result.returncode:
        return "", "Tesseract failed: " + result.stderr[-300:]
    return result.stdout, ""


def _extract_binary(path: Path) -> dict[str, Any]:
    _optional_pdf_deps()
    ext = path.suffix.lower()
    pages: list[dict[str, Any]] = []
    limitations: list[str] = []
    if ext == ".pdf":
        pypdf_text: list[str] = []
        fitz_text: list[str] = []
        try:
            import pypdf
            reader = pypdf.PdfReader(str(path))
            pypdf_text = [page.extract_text() or "" for page in reader.pages]
        except Exception as exc:  # optional extractor; cache the limitation
            limitations.append("pypdf text extraction unavailable: " + type(exc).__name__)
        try:
            import fitz
            doc = fitz.open(str(path))
            fitz_text = [page.get_text(sort=True) or "" for page in doc]
        except Exception as exc:
            limitations.append("PyMuPDF text extraction unavailable: " + type(exc).__name__)
            doc = None
        count = max(len(pypdf_text), len(fitz_text))
        for index in range(count):
            first = pypdf_text[index] if index < len(pypdf_text) else ""
            second = fitz_text[index] if index < len(fitz_text) else ""
            text = second or first
            pages.append({"page": index + 1, "text": text, "text_layer_checks": {
                "pypdf_sha256": hashlib.sha256(first.encode("utf-8")).hexdigest() if first else "",
                "pymupdf_sha256": hashlib.sha256(second.encode("utf-8")).hexdigest() if second else "",
                "text_layers_agree": bool(first and second and re.sub(r"\s+", " ", first).strip() == re.sub(r"\s+", " ", second).strip()),
            }})
        if not any(p["text"].strip() for p in pages):
            if doc is not None:
                for index, page in enumerate(doc):
                    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                    with tempfile.TemporaryDirectory(prefix="ghost_pdf_ocr_") as temp:
                        image = Path(temp) / f"page_{index + 1}.png"
                        pix.save(str(image))
                        text, limitation = _ocr_image(image)
                    pages.append({"page": index + 1, "text": text, "region": "full_page_ocr"})
                    if limitation:
                        limitations.append(limitation)
            else:
                limitations.append("PDF has no extracted text and could not be rendered for OCR.")
    elif ext == ".png":
        try:
            from PIL import Image
            with Image.open(path) as image:
                size = list(image.size)
            text, limitation = _ocr_image(path)
            pages.append({"page": 1, "region": "full_image", "dimensions": size, "text": text})
            if limitation:
                limitations.append(limitation)
        except Exception as exc:
            limitations.append("Image OCR/metadata unavailable: " + type(exc).__name__)
    return {"pages": pages, "text": "\n\n".join(p.get("text", "") for p in pages),
            "limitations": list(dict.fromkeys(limitations)),
            "ocr_available": bool(shutil.which("tesseract"))}


def build_evidence_cache(root: Path, cache_dir: Path | None = None, force: bool = False) -> dict[str, Any]:
    root = Path(root).resolve()
    cache_dir = Path(cache_dir or root / "cache/evidence_v2").resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    data = load(root)
    manifest = data["evidence_files"]
    units_by_evidence: dict[str, list[dict[str, Any]]] = {}
    scopes_by_evidence: dict[str, list[dict[str, Any]]] = {}
    for unit in data["units"]:
        units_by_evidence.setdefault(unit["evidence_id"], []).append(unit)
    for scope in data["scopes"]:
        scopes_by_evidence.setdefault(scope["evidence_id"], []).append(scope)

    written = 0
    reused = 0
    errors = []
    index = []
    for entry in manifest:
        source = (root / "dataset" / entry["file_path"]).resolve()
        if not source.is_relative_to((root / "dataset/evidence").resolve()):
            raise ValueError("Evidence path escapes dataset/evidence")
        evidence_id = entry["file_id"]
        source_hash = _sha256(source)
        destination = cache_dir / f"{evidence_id}_normalized.json"
        if destination.exists() and not force:
            try:
                cached = json.loads(destination.read_text(encoding="utf-8"))
                if cached.get("source_hash") == source_hash and cached.get("normalization_version") == CACHE_VERSION:
                    reused += 1
                    index.append({"evidence_id": evidence_id, "source_hash": source_hash,
                                  "cache_path": str(destination.relative_to(root)),
                                  "format": cached.get("format"), "record_count": len(cached.get("records", []))})
                    continue
            except (ValueError, OSError):
                pass
        ext = source.suffix.lower()
        records = []
        for unit in units_by_evidence.get(evidence_id, []):
            data_record = unit["data"]
            records.append({
                "record_location": unit["record_location"],
                "system_id": unit["system_id"],
                "resource_id": unit["resource_id"],
                "data_category": unit["data_category"],
                "timestamp": unit["observation_timestamp"],
                "evidence_timestamp": unit["evidence_timestamp"],
                "identifiers": sorted(_walk_identifiers(data_record)),
                "data": data_record,
                "text": unit["text"],
            })
        common = {"evidence_id": evidence_id, "source_hash": source_hash,
                  "source_path": entry["file_path"], "origin": entry.get("origin", ""),
                  "captured_at": entry["captured_at"], "format": ext.lstrip("."),
                  "records": records, "resource_ids": sorted({r["resource_id"] for r in records if r["resource_id"]}),
                  "identifiers": sorted({v for r in records for v in r["identifiers"]}),
                  "scopes": scopes_by_evidence.get(evidence_id, []), "text": "", "pages": [],
                  "limitations": [], "parse_errors": [e for e in data["parse_errors"] if e["evidence_id"] == evidence_id]}
        if ext in (".pdf", ".png"):
            try:
                extracted = _extract_binary(source)
                common.update(extracted)
                common["text"] = extracted["text"]
                common["identifiers"] = sorted(set(common["identifiers"]) | set(re.findall(
                    r"(?<![\w@.+-])(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\+?\d[\d ()-]{7,}\d|user_\d+|[a-z][a-z0-9_]*_\d+)(?![\w@.+-])",
                    extracted["text"], re.I)))
            except Exception as exc:
                common["limitations"].append("Binary extraction failed: " + type(exc).__name__)
                errors.append({"evidence_id": evidence_id, "error": type(exc).__name__})
        elif ext not in (".json", ".sql", ".log", ".txt"):
            common["limitations"].append("Unsupported participant evidence format.")
        if not records and not common["text"] and not common["limitations"]:
            common["limitations"].append("No record yielded by deterministic ingestion.")
        common["normalization_version"] = CACHE_VERSION
        destination.write_text(json.dumps(common, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written += 1
        index.append({"evidence_id": evidence_id, "source_hash": source_hash,
                      "cache_path": str(destination.relative_to(root)), "format": ext.lstrip("."),
                      "record_count": len(records)})

    manifest_path = cache_dir / "manifest.json"
    manifest_obj = {"source": "participant-facing dataset/evidence_files.csv",
                    "evidence_file_count": len(manifest), "cached_file_count": len(index),
                    "written": written, "reused": reused, "errors": errors, "files": index}
    manifest_path.write_text(json.dumps(manifest_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest_obj


def load_cached_evidence(root: Path, evidence_id: str) -> dict[str, Any]:
    path = Path(root) / "cache/evidence_v2" / f"{evidence_id}_normalized.json"
    if not path.exists():
        raise FileNotFoundError(f"Evidence cache missing for {evidence_id}")
    return json.loads(path.read_text(encoding="utf-8"))
