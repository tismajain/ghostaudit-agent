"""Bounded model observations; the tools and guard retain complete source records."""
from __future__ import annotations
import hashlib
import json

MAX_RECORDS = 4
MAX_SPAN_CHARS = 600
MAX_OBSERVATION_BYTES = 5000
MAX_HISTORY_BYTES = 10000
COMPACT_AT_BYTES = 4500


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def size(value):
    return len(encoded(value).encode())


class ContextLimit(RuntimeError):
    pass


def bounded(value, path="", omissions=None):
    """Explicitly mark partial values: partial literals must never support claims."""
    omissions = omissions if omissions is not None else []
    if isinstance(value, str) and len(value) > MAX_SPAN_CHARS:
        omissions.append(path)
        return {"preview": value[:MAX_SPAN_CHARS], "partial": True,
                "sha256": hashlib.sha256(value.encode()).hexdigest()}
    if isinstance(value, list):
        if len(value) > MAX_RECORDS:
            omissions.append(path)
        return [bounded(x, f"{path}[{i}]", omissions) for i, x in enumerate(value[:MAX_RECORDS])]
    if isinstance(value, dict):
        return {k: bounded(v, f"{path}.{k}", omissions) for k, v in value.items()
                if k not in {"pages", "visual_artifacts", "source_hash", "source_path", "file_path"}}
    return value


def compact_observation(name, result, arguments=None):
    """No complete files, images, duplicated baseline/identity, or irrelevant pages."""
    arguments = arguments or {}
    if name == "inspect_evidence":
        records = result.get("records", [])
        value = {k: result.get(k) for k in ("evidence_id", "format", "captured_at", "limitations")}
        value["matched_records"] = [
            {"record_id": r.get("record_location"), "record_location": r.get("record_location"),
             "resource_id": r.get("resource_id"), "system_id": r.get("system_id"),
             "data_category": r.get("data_category"), "timestamp": r.get("observation_timestamp"),
             "identifiers": r.get("identifiers", []), "relevant_fields": r.get("data", {}),
             "exact_subject_anchor": r.get("exact_subject_anchor")}
            for r in records]
        # Structured records already carry literals; never duplicate their raw file text.
        if not records:
            text = result.get("text", "")
            offset = arguments.get("text_offset") or 0
            value["relevant_span"] = text[offset:offset + MAX_SPAN_CHARS]
            value["next_text_offset"] = offset + MAX_SPAN_CHARS if len(text) > offset + MAX_SPAN_CHARS else None
            value["visual_only"] = bool(result.get("visual_artifacts")) and not text.strip()
        value["record_count"] = result.get("record_count", len(records))
        value["next_record_offset"] = result.get("next_record_offset")
    elif name == "resolve_identity":
        value = {k: result.get(k) for k in ("user_id", "current_identifiers", "historical_identifiers", "search_identifiers", "conflicts", "collisions")}
    elif name == "get_baseline_assessment":
        value = {k: result.get(k) for k in ("intent", "conflicts", "fallback_notes", "resource_confidence")}
    elif name == "search_evidence":
        value = {"results": [{"evidence_id": r["evidence_id"],
                              "matches": r.get("record_matches", []),
                              "matched_terms": r.get("text_matched_terms", [])}
                             for r in result.get("results", [])],
                 "total": result.get("search", {}).get("result_count"),
                 "searched_terms": result.get("search", {}).get("terms", []),
                 "next_offset": result.get("next_offset")}
    elif name == "list_candidate_evidence":
        value = {"candidate_evidence": [{k: r.get(k) for k in
                  ("evidence_id", "format", "captured_at", "matched_record_locations", "matched_identifiers", "limitations")}
                  for r in result.get("candidate_evidence", [])], "eligible_count": result.get("eligible_count"), "next_offset": result.get("next_offset")}
    elif name == "get_resource_timeline":
        value = {**result, "events": sorted(result.get("events", []), key=lambda r:r.get("event_time", "")),
                 "observations": sorted(result.get("observations", []), key=lambda r:r.get("timestamp", ""))}
    else:
        value = result
    omissions = []
    value = bounded(value, omissions=omissions)
    value["truncated"] = bool(omissions or value.get("next_record_offset") or value.get("next_text_offset") or value.get("next_offset") or result.get("truncated"))
    value["partial_paths"] = omissions
    while size(value) > MAX_OBSERVATION_BYTES:
        lists = [(k,v) for k,v in value.items() if isinstance(v,list) and v and k != 'partial_paths']
        if not lists:
            # Never silently erase an atomic record. Tell model to target a resource.
            return {"truncated": True, "unresolved": "Observation exceeds context budget; inspect a specific resource or request the next offset.",
                    "evidence_id": result.get("evidence_id"), "full_result_sha256": hashlib.sha256(encoded(result).encode()).hexdigest()}
        k, vals = max(lists, key=lambda kv:size(kv[1])); vals.pop()
        value["truncated"] = True
        if k not in value["partial_paths"]:value["partial_paths"].append(k)
    return value


class ModelContext:
    def __init__(self, case):
        self.case = case
        self.interactions = []
        self.seen = set()
        self.memory = {"confirmed_facts": [], "rejected_hypotheses": [], "unresolved_questions": [],
                       "inspected_evidence_ids": [], "resources_investigated": []}
        self.compactions = 0

    def add(self, event):
        digest = hashlib.sha256(encoded(event).encode()).hexdigest()
        if digest in self.seen:
            return False
        self.seen.add(digest)
        self.interactions.append(event)
        return True

    def observation(self, tool, result, args):
        obs = compact_observation(tool, result, args)
        if args.get("evidence_id") and tool == "inspect_evidence":
            self._remember("inspected_evidence_ids", args["evidence_id"])
        if args.get("resource_id"):
            self._remember("resources_investigated", args["resource_id"])
        for r in obs.get("matched_records", []):
            if r.get("resource_id"):self._remember("resources_investigated", r["resource_id"])
        if obs.get("truncated"):
            self._remember("unresolved_questions", {"tool": tool, "arguments": args, "reason": "partial observation; target resource/offset before claiming omitted facts"})
        event = {"event": "TOOL_RESULT", "tool_name": tool, "result": obs}
        if not self.add(event):
            # Give the pending call an explicit response without resending data.
            digest = hashlib.sha256(encoded(event).encode()).hexdigest()
            reference = {"event": "OBSERVATION_REFERENCE", "tool_name": tool,
                "sha256": digest, "unchanged": True,
                "instruction": "Already observed; choose a different grounded path or FINISH with explicit evidence limitations."}
            self.interactions.append(reference)
            return size(reference)
        return size(obs)

    def _remember(self, key, item):
        if item not in self.memory[key]:self.memory[key].append(item)

    def guard(self, result):
        verdicts = []
        for r in result.get("results", []):
            f=r.get("finding", {})
            v={"status": r.get("status"), "reason": r.get("reason"),
               "finding": f}
            verdicts.append(v)
            key = "confirmed_facts" if v["status"] == "CONFIRMED" else "rejected_hypotheses" if v["status"] == "REJECTED" else "unresolved_questions"
            self._remember(key, v)
        self.add({"event": "GUARD_FEEDBACK", "verdicts": verdicts})

    def history(self):
        events = [self.case, *self.interactions]
        if size(events) > COMPACT_AT_BYTES:
            self.compactions += 1
            # Preserve the latest complete action/result pair; semantic state is
            # accumulated independently of the interaction log and never clipped.
            self.interactions = self.interactions[-2:]
        if self.compactions:
            events = [self.case, {"event": "INVESTIGATION_SUMMARY", **self.memory}, *self.interactions]
        else:
            events = [self.case, *self.interactions]
        if size(events) > MAX_HISTORY_BYTES:
            raise ContextLimit("Semantic investigation state exceeds model-context limit; full trace retained")
        return events
