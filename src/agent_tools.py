"""Case-bound, allowlisted agent tools backed only by participant-facing inputs."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from src.evidence_cache import load_cached_evidence
from src.identity import exact_contains, match
from src.ingest import read_csv, read_ids
from src.schemas import timestamp

TOOL_NAMES = (
    "resolve_identity", "list_candidate_evidence", "search_evidence", "inspect_evidence",
    "search_activity", "get_resource_timeline", "get_policy", "get_baseline_assessment",
    "validate_findings",
)
TOOL_REQUIRED_ARGS = {
    "resolve_identity": {"case_id"}, "list_candidate_evidence": {"case_id"},
    "search_evidence": {"terms", "before_time"}, "inspect_evidence": {"evidence_id"},
    "search_activity": set(), "get_resource_timeline": {"resource_id", "audit_at"},
    "get_policy": {"data_category"}, "get_baseline_assessment": {"case_id"},
    "validate_findings": {"findings"},
}
TOOL_ALLOWED_ARGS = {
    "resolve_identity": {"case_id"}, "list_candidate_evidence": {"case_id", "offset"},
    "search_evidence": {"terms", "before_time", "resource_type", "offset"},
    "inspect_evidence": {"evidence_id", "resource_id", "record_offset", "text_offset"},
    "search_activity": {"identifiers", "resource_id", "start", "end", "offset"},
    "get_resource_timeline": {"resource_id", "audit_at", "offset"},
    "get_policy": {"data_category", "offset"}, "get_baseline_assessment": {"case_id"},
    "validate_findings": {"findings"},
}


def validate_tool_arguments(name: str, arguments: Any) -> dict[str, Any]:
    """Validate the tool allowlist and required/optional arguments before dispatch."""
    if name not in TOOL_NAMES:
        raise ValueError("Unknown tool name")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be a native JSON object")
    if any(not isinstance(key, str) for key in arguments):
        raise ValueError("Tool argument names must be strings")
    unknown = set(arguments) - TOOL_ALLOWED_ARGS[name]
    missing = TOOL_REQUIRED_ARGS[name] - set(arguments)
    if unknown:
        raise ValueError("Unknown argument(s) for " + name + ": " + ", ".join(sorted(unknown)))
    if missing:
        raise ValueError("Missing required argument(s) for " + name + ": " + ", ".join(sorted(missing)))
    clean = dict(arguments)
    for key in ("offset", "record_offset", "text_offset"):
        if key in clean and (isinstance(clean[key], bool) or not isinstance(clean[key], int) or clean[key] < 0):
            raise ValueError(key + " must be a nonnegative integer")
    string_args = {"case_id", "before_time", "resource_type", "evidence_id", "resource_id", "start", "end", "audit_at", "data_category"}
    for key in string_args & clean.keys():
        if clean[key] is not None and not isinstance(clean[key], str):
            raise ValueError(f"{name}.{key} must be a string")
    if name in ("resolve_identity", "list_candidate_evidence", "get_baseline_assessment", "get_policy", "get_resource_timeline", "inspect_evidence"):
        for key in TOOL_REQUIRED_ARGS[name]:
            if not isinstance(clean.get(key), str) or not clean[key]:
                raise ValueError(f"{name}.{key} must be a non-empty string")
    for key in ("case_id", "evidence_id", "resource_id"):
        if clean.get(key) is not None and not re.fullmatch(r"[a-z][a-z0-9_]*_[0-9]+", clean[key]):
            raise ValueError(key + " must be a literal participant identifier")
    if name == "search_evidence":
        if not isinstance(clean["terms"], list) or not clean["terms"] or any(not isinstance(x, str) or len(x.strip()) < 3 for x in clean["terms"]):
            raise ValueError("search_evidence.terms must be a non-empty array of exact strings")
        if not clean["before_time"]:
            raise ValueError("search_evidence.before_time must be non-empty")
    if name == "search_activity":
        identifiers = clean.get("identifiers")
        resource_id = clean.get("resource_id")
        if identifiers is not None and (not isinstance(identifiers, list) or any(not isinstance(x, str) or not x for x in identifiers)):
            raise ValueError("search_activity.identifiers must be an array of exact strings")
        if not identifiers and not resource_id:
            raise ValueError("search_activity needs identifiers or resource_id")
    if name == "validate_findings" and not isinstance(clean["findings"], list):
        raise ValueError("validate_findings.findings must be an array")
    return clean


class AgentTools:
    def __init__(self, root: Path, case_id: str, data: dict[str, Any], baseline_dir: Path | None = None):
        self.root = Path(root).resolve()
        self.case_id = case_id
        allowed_cases = {r['case_id'] for r in data.get('sample_deletion_requests', []) + data.get('deletion_requests', [])}
        if case_id not in allowed_cases:
            raise ValueError("Case is outside the supplied participant request tables")
        self.data = data
        self.baseline_dir = Path(baseline_dir or self.root / "runs/baseline_best_effort_v06")
        self.trace = json.loads((self.baseline_dir / "dev_traces" / f"{case_id}.json").read_text(encoding="utf-8"))
        prediction_rows = read_csv(self.baseline_dir / "dev_predictions.csv")
        row = next((r for r in prediction_rows if r["case_id"] == case_id), None)
        if row is None:
            raise ValueError("No baseline prediction for DEV case")
        self.baseline = {"case_id": case_id, "deletion_status": row["deletion_status"],
                         "steps": json.loads(row["steps_json"])}
        self.cut = timestamp(self.trace["request"]["audit_at"])
        self.manifest = {e["file_id"]: e for e in data["evidence_files"]
                         if timestamp(e["captured_at"]) <= self.cut}
        scope_path = self.root / "analysis/dev_evidence_scope.csv"
        self.scoped_candidate_ids: list[str] = list(self.trace.get("candidate_evidence_ids", []))
        if scope_path.exists() and not self.scoped_candidate_ids:
            scope_row = next((r for r in read_csv(scope_path) if r["case_id"] == case_id), None)
            if scope_row:
                self.scoped_candidate_ids = [eid for eid in json.loads(scope_row["identifier_matching_evidence_ids"])
                                             if eid in self.manifest]
        self.cache: dict[str, dict[str, Any]] = {}
        self.allowed: set[str] = set()
        self.inspected: set[str] = set()
        self.tool_log: list[dict[str, Any]] = []
        self.log = self.tool_log
        self.search_log: list[dict[str, Any]] = []
        self.confirmed_facts: list[dict[str, Any]] = []
        self.guard_results: list[dict[str, Any]] = []
        self.observed_resource_ids = {f["resource_id"] for f in self.trace.get("facts", []) if f.get("resource_id")}
        self.observed_resource_ids.update(self.trace.get("retrieval", {}).get("discovered_resources", []))

    def _check_case(self, case_id: str) -> None:
        if case_id != self.case_id:
            raise ValueError("Cross-case access denied")

    def _cache_item(self, evidence_id: str) -> dict[str, Any]:
        if evidence_id not in self.manifest:
            raise ValueError("Unknown or post-audit evidence")
        if evidence_id not in self.cache:
            self.cache[evidence_id] = load_cached_evidence(self.root, evidence_id)
        return self.cache[evidence_id]

    def _identity_terms(self) -> set[str]:
        identity = self.trace.get("resolved_identity", {})
        return {str(v) for v in identity.get("search_identifiers", []) if v}

    def _contains_anchor(self, item: dict[str, Any]) -> bool:
        identity = self.trace.get("resolved_identity", {})
        if not identity.get("user_id"):
            return False
        if match(json.dumps(item, ensure_ascii=False), identity):
            return True
        return any(exact_contains(json.dumps(item, ensure_ascii=False), term) for term in self._identity_terms())

    def resolve_identity(self, case_id: str) -> dict[str, Any]:
        self._check_case(case_id)
        identity = self.trace.get("resolved_identity", {})
        return {"case_id": case_id, "user_id": identity.get("user_id"),
                "current_identifiers": identity.get("current_identifiers", {}),
                "historical_identifiers": identity.get("historical_identifiers", {}),
                "search_identifiers": identity.get("search_identifiers", []),
                "identity_source_rows": identity.get("identity_source_rows", []),
                "ownership_intervals": identity.get("ownership_intervals", []),
                "collisions": identity.get("collisions", []), "conflicts": identity.get("conflicts", [])}

    def list_candidate_evidence(self, case_id: str, offset: int = 0) -> dict[str, Any]:
        self._check_case(case_id)
        candidates = []
        terms = self._identity_terms()
        for eid in self.scoped_candidate_ids:
            manifest = self.manifest[eid]
            normalized = self._cache_item(eid)
            matching_records = [r for r in normalized.get("records", []) if self._contains_anchor(r.get("data", {}))]
            matched_text_terms = [term for term in terms if exact_contains(normalized.get("text", ""), term)]
            if matching_records or matched_text_terms:
                self.allowed.add(eid)
                candidates.append({"evidence_id": eid, "file_path": manifest["file_path"],
                                   "origin": manifest.get("origin", ""), "captured_at": manifest["captured_at"],
                                   "format": normalized.get("format", ""),
                                   "matched_record_locations": [r["record_location"] for r in matching_records[:20]],
                                   "matched_identifiers": sorted({v for r in matching_records for v in r.get("identifiers", []) if v in terms} | set(matched_text_terms)),
                                   "text_available": bool(normalized.get("text")),
                                   "limitations": normalized.get("limitations", [])})
        return {"case_id": case_id, "candidate_evidence": candidates[offset:offset+4], "next_offset": offset+4 if len(candidates)>offset+4 else None,
                "scope_source": "precomputed exact-identifier evidence scope" if self.scoped_candidate_ids else "no exact-anchor file; use search_evidence if justified",
                "scope_basis": "Exact current/historical identifier in parsed records or extracted text; manifest metadata alone is not ownership proof.",
                "eligible_count": len(candidates)}

    def search_evidence(self, terms: list[str], before_time: str, resource_type: str | None = None, offset: int = 0) -> dict[str, Any]:
        if not isinstance(terms, list) or not terms or any(not isinstance(x, str) or len(x.strip()) < 3 for x in terms):
            raise ValueError("search_evidence requires one or more exact literal terms")
        if timestamp(before_time) > self.cut:
            raise ValueError("Search cutoff may not exceed audit_at")
        hits = []
        for eid, manifest in self.manifest.items():
            normalized = self._cache_item(eid)
            if timestamp(manifest["captured_at"]) > timestamp(before_time):
                continue
            record_hits = []
            for record in normalized.get("records", []):
                raw = json.dumps(record.get("data", {}), ensure_ascii=False)
                matched = [term for term in terms if exact_contains(raw, term)]
                if matched and (not resource_type or resource_type.lower() in (record.get("data_category", "") + " " + record.get("system_id", "")).lower()):
                    record_hits.append({"record_location": record["record_location"], "resource_id": record["resource_id"],
                                        "system_id": record["system_id"], "data_category": record["data_category"],
                                        "matched_terms": matched})
            text = normalized.get("text", "")
            text_hits = [term for term in terms if exact_contains(text, term)]
            if record_hits or text_hits:
                self.allowed.add(eid)
                hits.append({"evidence_id": eid, "file_path": manifest["file_path"], "origin": manifest.get("origin", ""),
                             "captured_at": manifest["captured_at"], "record_matches": record_hits[:30],
                             "text_matched_terms": text_hits})
        call = {"terms": terms, "before_time": before_time, "resource_type": resource_type,
                "result_count": len(hits), "evidence_ids": [h["evidence_id"] for h in hits]}
        self.search_log.append(call)
        return {"case_id": self.case_id, "search": call, "results": hits[offset:offset+4], "truncated": len(hits) > offset+4, "next_offset": offset+4 if len(hits)>offset+4 else None,
                "warning": "Exact matching is discovery only; the result does not prove resource ownership or state."}

    def inspect_evidence(self, evidence_id: str, resource_id: str | None = None, record_offset: int = 0, text_offset: int = 0) -> dict[str, Any]:
        if evidence_id not in self.manifest:
            raise ValueError("Evidence is unknown or captured after audit_at")
        if evidence_id not in self.allowed:
            raise ValueError("Inspect only a file returned by list_candidate_evidence or search_evidence")
        normalized = self._cache_item(evidence_id)
        self.inspected.add(evidence_id)
        if resource_id:
            self.observed_resource_ids.add(resource_id)
        records = []
        for record in normalized.get("records", []):
            if resource_id and record.get("resource_id") != resource_id:
                continue
            anchored = self._contains_anchor(record.get("data", {}))
            if anchored or resource_id and record.get("resource_id") == resource_id:
                records.append({**record, "exact_subject_anchor": anchored,
                                "other_user_ids_in_atomic_record": sorted(set(re.findall(
                                    r"\buser_\d+\b", json.dumps(record.get("data", {})))) -
                                    {self.trace.get("resolved_identity", {}).get("user_id", "")})})
                if record.get("resource_id"):
                    self.observed_resource_ids.add(record["resource_id"])
        result = {"evidence_id": evidence_id, "source_hash": normalized.get("source_hash"),
                  "source_path": normalized.get("source_path"), "format": normalized.get("format"),
                  "captured_at": normalized.get("captured_at"), "records": records[record_offset:], "next_record_offset": record_offset+4 if len(records)>record_offset+4 else None,
                  "record_count": len(records), "text": normalized.get("text", ""),
                  "pages": normalized.get("pages", []), "limitations": normalized.get("limitations", []),
                  "ownership_warning": "Same-file co-occurrence alone does not prove ownership."}
        if Path(normalized.get("source_path", "")).suffix.lower() in (".png", ".pdf"):
            path = self.root / "dataset" / normalized["source_path"]
            if path.suffix.lower() == ".png":
                result["visual_artifacts"] = [{"media_type": "image/png", "data_url": "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii"), "region": "full_image"}]
            elif not result["text"].strip():
                # Render only this dynamically requested, already-scoped PDF.
                _add_pdf_previews(path, result)
        return result

    def search_activity(self, identifiers: list[str] | None = None, resource_id: str | None = None,
                        start: str | None = None, end: str | None = None, offset: int = 0) -> dict[str, Any]:
        if not identifiers and not resource_id:
            raise ValueError("search_activity needs exact identifiers or a resource_id")
        lower = timestamp(start) if start else None
        upper = timestamp(end) if end else self.cut
        if upper > self.cut:
            raise ValueError("Activity end may not exceed audit_at")
        rows = []
        for event in self.data["system_activity"]:
            event_at = timestamp(event["event_time"])
            if event_at > upper or lower and event_at < lower:
                continue
            if resource_id and event.get("resource_id") == resource_id:
                rows.append(event)
                continue
            raw = json.dumps(event, ensure_ascii=False)
            matched = [x for x in (identifiers or []) if exact_contains(raw, x)]
            if matched:
                rows.append({**event, "matched_identifiers": matched})
        return {"case_id": self.case_id, "events": sorted(rows, key=lambda r:r["event_time"])[offset:offset+4], "event_count": len(rows), "truncated": len(rows) > offset+4, "next_offset": offset+4 if len(rows)>offset+4 else None,
                "warning": "reported_result is a claim and is never direct state evidence."}

    def get_resource_timeline(self, resource_id: str, audit_at: str, offset: int = 0) -> dict[str, Any]:
        if resource_id not in self.observed_resource_ids:
            raise ValueError("Timeline resource must first appear in baseline context or inspected evidence")
        if timestamp(audit_at) != self.cut:
            raise ValueError("audit_at must match the current case cutoff")
        observations = []
        for unit in self.data["units"]:
            if unit.get("resource_id") == resource_id and timestamp(unit["evidence_timestamp"]) <= self.cut and timestamp(unit["observation_timestamp"]) <= self.cut:
                observations.append({"evidence_id": unit["evidence_id"], "source_path": unit["source_path"],
                                     "record_location": unit["record_location"], "timestamp": unit["observation_timestamp"],
                                     "system_id": unit["system_id"], "data_category": unit["data_category"], "data": unit["data"]})
        events = [e for e in self.data["system_activity"] if e.get("resource_id") == resource_id and timestamp(e["event_time"]) <= self.cut]
        return {"resource_id": resource_id, "audit_at": audit_at, "observations": sorted(observations, key=lambda r:r["timestamp"])[offset:offset+4],
                "events": sorted(events, key=lambda r:r["event_time"])[offset:offset+4],
                "next_offset": offset+4 if max(len(events), len(observations))>offset+4 else None, "warning": "Conflicting observations are shown together; no latest-wins precedence applied."}

    def get_policy(self, data_category: str, offset: int = 0) -> dict[str, Any]:
        rules = [r for r in self.data["deletion_rules"] if r["data_category"] == data_category]
        return {"data_category": data_category, "rules": rules[offset:offset+4],
                "next_offset": offset+4 if len(rules)>offset+4 else None,
                "note": "The policy condition still requires participant-visible evidence."}

    def get_baseline_assessment(self, case_id: str) -> dict[str, Any]:
        self._check_case(case_id)
        return {"case_id": case_id, "prediction": self.baseline,
                "intent": self.trace.get("intent", {}), "resolved_identity": self.trace.get("resolved_identity", {}),
                "facts": self.trace.get("facts", []), "conflicts": self.trace.get("conflicts", []),
                "resource_confidence": self.trace.get("resource_confidence", {}),
                "policy_decisions": self.trace.get("policy_decisions", []),
                "fallback_notes": self.trace.get("fallback_notes", []),
                "step_confidence": self.trace.get("step_confidence", [])}

    def validate_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        from src.guard import validate_findings
        result = validate_findings(findings, self)
        self.guard_results.extend(result["results"])
        self.confirmed_facts.extend(result["validated_facts"])
        return result

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {"tool": name, "arguments": arguments}
        target_log = getattr(self, "tool_log", None)
        if target_log is None:
            target_log = getattr(self, "log", None)
            if target_log is None:
                target_log = []
            self.tool_log = target_log
        target_log.append(record)
        try:
            normalized_args = validate_tool_arguments(name, arguments)
            result = getattr(self, name)(**normalized_args)
            if not isinstance(result, dict):
                raise TypeError("Tool response must be a structured JSON object")
            json.dumps(result)
        except Exception as exc:
            result = {"error": str(exc), "denied": True}
        record["result"] = _without_visual_bytes(result)
        return result

    # Compatibility alias for the previous shadow prototype; never exposed in live tool schemas.
    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        aliases = {"get_case_context": "get_baseline_assessment", "get_baseline_prediction": "get_baseline_assessment",
                   "get_resolved_identity": "resolve_identity", "get_candidate_evidence": "list_candidate_evidence",
                   "search_evidence_exact": "search_evidence"}
        name = aliases.get(name, name)
        if name == "search_evidence":
            default_cut = getattr(self, "trace", {}).get("request", {}).get("audit_at", "")
            arguments = {"terms": arguments.get("terms", []), "before_time": arguments.get("audit_at", default_cut)}
        if name == "inspect_evidence" and "resource_id" not in arguments and "query" in arguments:
            terms = arguments.pop("query")
            arguments = {"evidence_id": arguments["evidence_id"], "resource_id": next((x for x in terms if re.fullmatch(r"[a-z][a-z0-9_]*_\d+", str(x))), None)}
        if name in ("resolve_identity", "list_candidate_evidence", "get_baseline_assessment"):
            arguments.setdefault("case_id", self.case_id)
        result = self.dispatch(name, arguments)
        # Previous prototype consumed response in a separate field.
        return result


def _without_visual_bytes(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ({"redacted_visual_payload": True, "length": len(v)} if k == "data_url" and isinstance(v, str) else _without_visual_bytes(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_without_visual_bytes(x) for x in value]
    return value


def _add_pdf_previews(path: Path, result: dict[str, Any]) -> None:
    try:
        import fitz
        doc = fitz.open(str(path))
        previews = []
        for index, page in enumerate(doc):
            pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
            if pix.width * pix.height > 3_000_000:
                continue
            raw = pix.tobytes("png")
            previews.append({"page": index + 1, "media_type": "image/png",
                             "data_url": "data:image/png;base64," + base64.b64encode(raw).decode("ascii")})
        result["visual_artifacts"] = previews[:8]
    except Exception as exc:
        result.setdefault("limitations", []).append("PDF preview unavailable: " + type(exc).__name__)
