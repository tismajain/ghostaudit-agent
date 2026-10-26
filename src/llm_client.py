"""OpenAI Responses adapter using native structured tool-argument objects."""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from src.agent_context import MAX_HISTORY_BYTES, size
from src.agent_tools import TOOL_NAMES, TOOL_ALLOWED_ARGS, TOOL_REQUIRED_ARGS, validate_tool_arguments

# A schema change intentionally invalidates v1 cache keys and response envelopes.
PROMPT_VERSION = "production-investigator-v3.3-compact-union"
FINDING_TYPES = ("RESOURCE_OWNERSHIP", "RESOURCE_STATE", "EXPOSED_PII",
                 "ACTIVE_DATA_FLOW", "RESTORE_RISK", "POLICY_CONDITION")

FINDING_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "type": {"type": "string", "enum": list(FINDING_TYPES)},
        "system_id": {"type": "string"}, "resource_id": {"type": "string"},
        "evidence_id": {"type": "string"}, "data_category": {"type": "string"},
        "state": {"type": "string"},
        "supporting_observation": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "record_location": {"type": "string"},
                "literal_fields": {"type": "array", "items": {
                    "type": "object", "additionalProperties": False,
                    "properties": {"field": {"type": "string"}, "value": {"type": "string"}},
                    "required": ["field", "value"]}},
                "condition_name": {"type": "string"}, "expected_value": {"type": "string"},
            },
            "required": ["record_location", "literal_fields", "condition_name", "expected_value"],
        },
    },
    "required": ["type", "system_id", "resource_id", "evidence_id", "data_category", "state", "supporting_observation"],
}

_NULLABLE_STRING = {"type": ["string", "null"]}
_ARGUMENT_SCHEMA_FIELDS = {
    "offset": {"type": ["integer", "null"]},
    "record_offset": {"type": ["integer", "null"]},
    "text_offset": {"type": ["integer", "null"]},
    "case_id": _NULLABLE_STRING,
    "terms": {"anyOf": [{"type": "array", "items": {"type": "string", "minLength": 3, "maxLength": 200}}, {"type": "null"}]},
    "before_time": _NULLABLE_STRING, "resource_type": _NULLABLE_STRING,
    "evidence_id": _NULLABLE_STRING, "resource_id": _NULLABLE_STRING,
    "identifiers": {"anyOf": [{"type": "array", "items": {"type": "string", "minLength": 3, "maxLength": 200}}, {"type": "null"}]},
    "start": _NULLABLE_STRING, "end": _NULLABLE_STRING, "audit_at": _NULLABLE_STRING,
    "data_category": _NULLABLE_STRING,
    "findings": {"anyOf": [{"type": "array", "items": FINDING_SCHEMA}, {"type": "null"}]},
}
def _object(properties):
    return {"type": "object", "additionalProperties": False,
            "properties": properties, "required": list(properties)}


# Root anyOf is unsupported by Responses Structured Outputs. A single action
# property permits a strict nested discriminated union with no overlapping fields.
_TOOL_BRANCHES = []
for _name in TOOL_NAMES:
    if _name == "validate_findings":
        continue  # findings go through PROPOSE_FINDINGS, never a tool-shaped action
    _fields = {}
    for _arg in sorted(TOOL_ALLOWED_ARGS[_name]):
        _field = _ARGUMENT_SCHEMA_FIELDS[_arg]
        if _arg in TOOL_REQUIRED_ARGS[_name]:
            if "anyOf" in _field:
                _field = _field["anyOf"][0]
            elif isinstance(_field.get("type"), list):
                _field = {"type": "string"}
        if _arg in {"case_id", "evidence_id", "resource_id"}:
            _field = {**_field, "pattern": r"^[a-z][a-z0-9_]*_[0-9]+$", "maxLength": 160}
        elif _arg in {"before_time", "start", "end", "audit_at"}:
            _field = {**_field, "maxLength": 40}
        _fields[_arg] = _field
    _TOOL_BRANCHES.append(_object({"name": {"type": "string", "enum": [_name]},
                                   "arguments": _object(_fields)}))
ACTION_SCHEMA = {"anyOf": [
    _object({"type": {"type": "string", "enum": ["TOOL_CALL"]},
             "tool": {"anyOf": _TOOL_BRANCHES}}),
    _object({"type": {"type": "string", "enum": ["PROPOSE_FINDINGS"]},
             "findings": {"type": "array", "minItems": 1, "maxItems": 8,
                          "items": {"$ref": "#/$defs/finding"}}}),
    _object({"type": {"type": "string", "enum": ["FINISH"]},
             "reason": {"type": "string", "maxLength": 300}, "assessment": {"type": "string", "maxLength": 300}}),
]}
RESPONSE_SCHEMA = {**_object({"action": ACTION_SCHEMA}), "$defs": {"finding": FINDING_SCHEMA}}


class ActionValidationError(ValueError):
    """The model response did not conform to the strict investigator contract."""


class ModelResponseInvalid(RuntimeError):
    def __init__(self, message: str, attempts: list[dict[str, Any]]):
        super().__init__(message)
        self.attempts = attempts


def _without_visual_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ({"visual_data_sha256": hashlib.sha256(v.encode()).hexdigest(), "length": len(v)}
                    if k == "data_url" and isinstance(v, str) else _without_visual_data(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_without_visual_data(x) for x in value]
    return value


def _visual_urls(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        if isinstance(value.get("data_url"), str) and value["data_url"].startswith("data:image/"):
            found.append(value["data_url"])
        for key, item in value.items():
            if key != "data_url":
                found.extend(_visual_urls(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_visual_urls(item))
    return found


def _finding_error(finding: Any, index: int) -> str | None:
    required = {"type", "system_id", "resource_id", "evidence_id", "data_category", "state", "supporting_observation"}
    if not isinstance(finding, dict) or set(finding) != required:
        return f"finding {index} must contain exactly the typed finding fields"
    if finding["type"] not in FINDING_TYPES:
        return f"finding {index} has an unknown finding type"
    for name in ("system_id", "resource_id", "evidence_id", "data_category", "state"):
        if not isinstance(finding[name], str):
            return f"finding {index}.{name} must be a string"
    if not finding["system_id"] or not finding["resource_id"] or not finding["evidence_id"]:
        return f"finding {index} must include non-empty system_id, resource_id, and evidence_id"
    observation = finding["supporting_observation"]
    obs_keys = {"record_location", "literal_fields", "condition_name", "expected_value"}
    if not isinstance(observation, dict) or set(observation) != obs_keys:
        return f"finding {index}.supporting_observation has invalid fields"
    if not all(isinstance(observation[k], str) for k in ("record_location", "condition_name", "expected_value")):
        return f"finding {index}.supporting_observation string fields are invalid"
    literal_fields = observation["literal_fields"]
    if not isinstance(literal_fields, list):
        return f"finding {index}.literal_fields must be an array"
    for pair in literal_fields:
        if not isinstance(pair, dict) or set(pair) != {"field", "value"} or not all(isinstance(pair[k], str) for k in pair):
            return f"finding {index}.literal_fields entries must contain string field/value"
    return None


def _normalize_nullable_arguments(arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ActionValidationError("arguments must be a native JSON object")
    unknown = set(arguments) - set(_ARGUMENT_SCHEMA_FIELDS)
    if unknown:
        raise ActionValidationError("unknown argument field(s): " + ", ".join(sorted(unknown)))
    return {k: v for k, v in arguments.items() if v is not None}


def _validate_action(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise ActionValidationError("action must be an object")
    kind = response.get("type")
    fields = {"TOOL_CALL": {"type", "tool"},
              "PROPOSE_FINDINGS": {"type", "findings"},
              "FINISH": {"type", "reason", "assessment"}}
    if not isinstance(kind, str) or kind not in fields:
        raise ActionValidationError("unknown action type")
    if set(response) != fields[kind]:
        raise ActionValidationError(kind + " must contain exactly " + ", ".join(sorted(fields[kind])))
    if kind == "TOOL_CALL":
        tool = response["tool"]
        if not isinstance(tool, dict) or set(tool) != {"name", "arguments"}:
            raise ActionValidationError("tool must contain exactly name and arguments")
        if not isinstance(tool["name"], str) or tool["name"] not in TOOL_NAMES or tool["name"] == "validate_findings":
            raise ActionValidationError("unknown tool name; use PROPOSE_FINDINGS for guard validation")
        if isinstance(tool["arguments"], dict) and set(tool["arguments"]) - TOOL_ALLOWED_ARGS[tool["name"]]:
            raise ActionValidationError("extraneous tool argument fields, including null fields, are forbidden")
        args = _normalize_nullable_arguments(tool["arguments"])
        try:
            args = validate_tool_arguments(tool["name"], args)
        except ValueError as exc:
            raise ActionValidationError(str(exc)) from None
        return {"type": kind, "tool": {"name": tool["name"], "arguments": args}}
    if kind == "PROPOSE_FINDINGS":
        findings = response["findings"]
        if not isinstance(findings, list) or not 1 <= len(findings) <= 8:
            raise ActionValidationError("PROPOSE_FINDINGS requires 1 to 8 findings")
        for index, finding in enumerate(findings):
            error = _finding_error(finding, index)
            if error:
                raise ActionValidationError(error)
    elif not all(isinstance(response[k], str) and response[k].strip() for k in ("reason", "assessment")):
        raise ActionValidationError("FINISH requires nonempty reason and assessment")
    return response


def _decode_action(raw_text):
    envelope = json.loads(raw_text)
    if not isinstance(envelope, dict) or set(envelope) != {"action"}:
        raise ActionValidationError("wire response must contain exactly action")
    return _validate_action(envelope["action"])


def _usage(response_obj: dict[str, Any]) -> dict[str, int]:
    raw = response_obj.get("usage", {})
    return {"input_tokens": raw.get("input_tokens", 0),
            "output_tokens": raw.get("output_tokens", 0),
            "total_tokens": raw.get("total_tokens", 0),
            "cached_input_tokens": raw.get("input_tokens_details", {}).get("cached_tokens", 0)}


def _estimate_cost(usage: dict[str, Any]) -> float | None:
    try:
        input_rate = float(os.environ["OPENAI_INPUT_USD_PER_1M"])
        output_rate = float(os.environ["OPENAI_OUTPUT_USD_PER_1M"])
    except (KeyError, ValueError):
        return None
    return usage.get("input_tokens", 0) * input_rate / 1_000_000 + usage.get("output_tokens", 0) * output_rate / 1_000_000


class OpenAIResponsesClient:
    def __init__(self, root: Path, model: str | None = None, cache_dir: Path | None = None,
                 endpoint: str | None = None, timeout: int = 120):
        self.root = Path(root).resolve()
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
        self.endpoint = endpoint or "https://api.openai.com/v1/responses"
        self.cache_dir = Path(cache_dir or self.root / "cache/model_responses").resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.call_log: list[dict[str, Any]] = []

    def context_metrics(self, system_prompt, history):
        messages = self._messages(system_prompt, history)
        return {"prompt_context_bytes": len(json.dumps(messages, ensure_ascii=False).encode()),
                "history_bytes": len(json.dumps(history, ensure_ascii=False).encode()),
                "history_size": len(history),
                "schema_bytes": len(json.dumps(RESPONSE_SCHEMA).encode())}

    def usage_summary(self) -> dict[str, Any]:
        calls = self.call_log
        model_calls = [c for c in calls if c.get("api_calls", 0)]
        return {"model": self.model, "calls": sum(c.get("api_calls", 0) for c in calls),
                "input_tokens": sum(c.get("usage", {}).get("input_tokens", 0) for c in calls),
                "output_tokens": sum(c.get("usage", {}).get("output_tokens", 0) for c in calls),
                "total_tokens": sum(c.get("usage", {}).get("total_tokens", 0) for c in calls),
                "estimated_cost_usd": (sum(c.get("cost_usd", 0) for c in model_calls)
                                        if model_calls and all(c.get("cost_usd") is not None for c in model_calls) else None),
                "modes": {mode: sum(c.get("mode") == mode for c in calls) for mode in ("live", "replay")},
                "replay_cache_hits": sum(c.get("cache_hit", False) for c in calls),
                "primary_calls": sum(c.get("call_type") == "primary" for c in calls),
                "repair_calls": sum(c.get("call_type") == "repair" for c in calls),
                "invalid_responses": sum(bool(c.get("validation_error")) for c in calls),
                "successful_responses": sum(c.get("successful", False) for c in calls)}

    def _key(self, system_prompt: str, history: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        input_obj = {"model": self.model, "prompt_version": PROMPT_VERSION,
                     "response_schema": "exclusive-actions-v3.3", "system_prompt": system_prompt,
                     "history": _without_visual_data(history),
                     "visual_hashes": [hashlib.sha256(v.encode()).hexdigest() for v in _visual_urls(history)]}
        canonical = json.dumps(input_obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), input_obj

    def _messages(self, system_prompt: str, history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        messages = [{"role": "system", "content": [{"type": "input_text", "text": system_prompt}]}]
        for event in history:
            text_event = _without_visual_data(event)
            parts = [{"type": "input_text", "text": json.dumps(text_event, ensure_ascii=False, separators=(",", ":"))}]
            parts.extend({"type": "input_image", "image_url": url, "detail": "high"} for url in _visual_urls(event))
            messages.append({"role": "user", "content": parts})
        return messages

    def _request_live(self, system_prompt: str, history: list[dict[str, Any]], key: str) -> tuple[str, dict[str, Any], str]:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            call = {"model": self.model, "mode": "live", "cache_key": key,
                    "error": "OPENAI_API_KEY is not set", "usage": {}, "api_calls": 0,
                    "billed_input_tokens": 0, "billed_output_tokens": 0, "cost_usd": 0.0}
            self.call_log.append(call)
            raise RuntimeError("OPENAI_API_KEY is not set")
        payload = {"model": self.model, "input": self._messages(system_prompt, history), "temperature": 0,
                   "max_output_tokens": 1800,
                   "text": {"format": {"type": "json_schema", "name": "agent_action", "strict": True,
                                       "schema": RESPONSE_SCHEMA}}}
        request = urllib.request.Request(self.endpoint, data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as stream:
                response_obj = json.loads(stream.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read(1000).decode("utf-8", errors="replace").replace(api_key, "[REDACTED]")
            body = re.sub(r"sk-[A-Za-z0-9_-]+", "[REDACTED]", body)
            call = {"model": self.model, "mode": "live", "cache_key": key,
                    "error": f"HTTP {exc.code}: {body}", "usage": {}, "api_calls": 1,
                    "billed_input_tokens": 0, "billed_output_tokens": 0, "cost_usd": None}
            self.call_log.append(call)
            raise RuntimeError(call["error"]) from None
        except Exception as exc:
            call = {"model": self.model, "mode": "live", "cache_key": key,
                    "error": type(exc).__name__ + ": " + str(exc), "usage": {}, "api_calls": 1,
                    "billed_input_tokens": 0, "billed_output_tokens": 0, "cost_usd": None}
            self.call_log.append(call)
            raise RuntimeError(call["error"]) from None
        text = response_obj.get("output_text", "")
        if not text:
            for item in response_obj.get("output", []):
                for content in item.get("content", []):
                    if content.get("type") == "output_text":
                        text = content.get("text", "")
        usage = _usage(response_obj)
        call = {"model": self.model, "mode": "live", "cache_key": key, "response_id": response_obj.get("id"),
                "usage": usage, "api_calls": 1, "billed_input_tokens": usage["input_tokens"],
                "billed_output_tokens": usage["output_tokens"], "cost_usd": _estimate_cost(usage)}
        return text, call, response_obj.get("id", "")

    def respond(self, system_prompt: str, history: list[dict[str, Any]], mode: str,
                max_repairs: int = 2) -> tuple[dict[str, Any], dict[str, Any]]:
        if mode not in ("live", "replay"):
            raise ValueError("mode must be live or replay")
        if max_repairs < 0 or max_repairs > 2:
            raise ValueError("max_repairs must be between 0 and 2")
        original_key, _ = self._key(system_prompt, history)
        original_path = self.cache_dir / f"{original_key}.json"
        if mode == "replay":
            if not original_path.exists():
                raise KeyError("Replay cache miss: " + original_key)
            try:
                cached = json.loads(original_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                raise ModelResponseInvalid("Replay cache envelope is invalid: " + str(exc), []) from None
            if cached.get("prompt_version") != PROMPT_VERSION or cached.get("response_schema") != "exclusive-actions-v3.3":
                raise ModelResponseInvalid("Cached response uses an incompatible response schema", [])
            try:
                action = _validate_action(cached.get("response"))
            except (ActionValidationError, TypeError) as exc:
                raise ModelResponseInvalid("Cached response failed validation: " + str(exc), []) from None
            usage = dict(cached.get("usage", {}))
            call = {"model": self.model, "mode": "replay", "cache_key": original_key, "cache_hit": True,
                    "usage": usage, "api_calls": 0, "billed_input_tokens": 0,
                    "billed_output_tokens": 0, "cost_usd": 0.0,
                    "source_model_calls": cached.get("model_calls", 1),
                    "repair_count": cached.get("repair_count", 0),
                    "repair_errors": cached.get("repair_errors", []),
                    "call_type": "replay", "successful": True,
                    **self.context_metrics(system_prompt, history)}
            self.call_log.append(call)
            return action, call

        working_history = list(history)
        attempts: list[dict[str, Any]] = []
        aggregate_usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cached_input_tokens": 0}
        validation_errors: list[str] = []
        expected_signature: str | None = None
        for attempt_no in range(max_repairs + 1):
            if size(working_history) > MAX_HISTORY_BYTES:
                raise ModelResponseInvalid("Repair/model context exceeds hard byte limit; full trace retained", attempts)
            key, _ = self._key(system_prompt, working_history)
            try:
                raw_text, call, response_id = self._request_live(system_prompt, working_history, key)
            except RuntimeError:
                if self.call_log:
                    self.call_log[-1].update({"call_type": "repair" if attempt_no else "primary",
                        "successful": False, **self.context_metrics(system_prompt, working_history)})
                raise
            api_call = self.call_log[-1] if self.call_log and self.call_log[-1].get("cache_key") == key else call
            # The transport records token usage before validation, so invalid model output
            # and every repair call remain visible in accounting.
            for field in aggregate_usage:
                aggregate_usage[field] += call.get("usage", {}).get(field, 0)
            decoded = None
            try:
                decoded = json.loads(raw_text)
                action = _decode_action(raw_text)
                if expected_signature and action["type"] != expected_signature:
                    raise ActionValidationError("repair changed the original action kind or tool name")
            except (json.JSONDecodeError, ActionValidationError, TypeError) as exc:
                message = f"{type(exc).__name__}: {exc}"
                validation_errors.append(message)
                call.update({"validation_error": message, "attempt": attempt_no + 1, "call_type": "repair" if attempt_no else "primary", "successful": False, **self.context_metrics(system_prompt, working_history)})
                self.call_log.append(call)
                attempts.append({"attempt": attempt_no + 1, "validation_error": message,
                                 "response_id": response_id, "usage": call.get("usage", {})})
                if expected_signature is None and isinstance(decoded, dict):
                    intended = decoded.get("action", {})
                    if isinstance(intended, dict):
                        expected_signature = intended.get("type")
                if attempt_no >= max_repairs:
                    raise ModelResponseInvalid("Model response remained invalid after bounded repairs: " + message,
                                               attempts) from None
                # Provide the validation feedback and ask for the same intended action
                # in the schema. No heuristic JSON rewriting is performed.
                working_history.append({"event": "ACTION_VALIDATION_REPAIR",
                    "instruction": "Re-emit the same intended action using the required strict response schema. Do not change the investigation claim; correct only response structure/arguments.",
                    "validation_error": message, "invalid_response": raw_text[:500]})
                continue
            call.update({"attempt": attempt_no + 1, "validation_error": None, "call_type": "repair" if attempt_no else "primary", "successful": True, **self.context_metrics(system_prompt, working_history)})
            self.call_log.append(call)
            total_model_calls = len(attempts) + 1
            replay_record = {"model": self.model, "prompt_version": PROMPT_VERSION,
                "response_schema": "exclusive-actions-v3.3", "cache_key": original_key,
                "input_hash": original_key, "usage": aggregate_usage, "model_calls": total_model_calls,
                "repair_count": attempt_no, "repair_errors": validation_errors, "response": action}
            original_path.write_text(json.dumps(replay_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            final_call = dict(call, usage=aggregate_usage, api_calls=total_model_calls,
                              repair_count=attempt_no, repair_errors=validation_errors)
            return action, final_call
        raise AssertionError("bounded response loop fell through")
