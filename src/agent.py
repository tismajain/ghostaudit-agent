"""Bounded investigator loop. The model proposes typed facts; Python owns plans."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.agent_context import ModelContext, ContextLimit, size
from src.agent_tools import AgentTools, _without_visual_bytes
from src.guard import validate_findings
from src.llm_client import ModelResponseInvalid, OpenAIResponsesClient

SYSTEM_PROMPT = (Path(__file__).with_name("agent_system_prompt.md")).read_text(encoding="utf-8")


def investigate(root: Path, case_id: str, data: dict[str, Any], *, mode: str,
                max_turns: int = 8, baseline_dir: Path | None = None,
                client: OpenAIResponsesClient | None = None) -> dict[str, Any]:
    if max_turns < 1:
        raise ValueError("max_turns must be positive")
    root = Path(root).resolve()
    tools = AgentTools(root, case_id, data, baseline_dir)
    client = client or OpenAIResponsesClient(root)
    start_call_index = len(client.call_log)
    prompt = SYSTEM_PROMPT
    req = tools.trace["request"]
    case_event = {"event": "CASE", "case_id": case_id,
        "audit_at": req["audit_at"], "request_text": req["request_text"],
        "turn_budget": max_turns,
        "subject_identifiers": tools.trace.get("resolved_identity", {}).get("search_identifiers", [])}
    context = ModelContext(case_event)
    full_history = [case_event]
    decisions, proposals, guards, turn_metrics = [], [], [], []
    stop_reason = "TURN_LIMIT"
    last_tool_bytes = 0
    turn_start = start_call_index
    turns = 0
    replay_miss = None
    response_invalid = None
    finished = False
    for turn in range(max_turns):
        turns += 1
        turn_start = len(client.call_log)
        try:
            history = context.history()
            turn_start = len(client.call_log)
            action, call = client.respond(prompt, history, mode)
        except ContextLimit as exc:
            stop_reason = "CONTEXT_LIMIT"
            decisions.append({"turn": turns, "decision": stop_reason, "detail": str(exc)})
            break
        except KeyError as exc:
            stop_reason = "REPLAY_CACHE_MISS"
            replay_miss = str(exc)
            decisions.append({"turn": turn + 1, "decision": "REPLAY_CACHE_MISS", "detail": replay_miss})
            break
        except ModelResponseInvalid as exc:
            stop_reason = "MODEL_RESPONSE_INVALID"
            response_invalid = {"message": str(exc), "attempts": exc.attempts}
            decisions.append({"turn": turn + 1, "decision": "MODEL_RESPONSE_INVALID",
                              "detail": response_invalid})
            break
        except RuntimeError as exc:
            stop_reason = "MODEL_ERROR"
            decisions.append({"turn": turn + 1, "decision": "MODEL_ERROR", "detail": str(exc)})
            break
        turn_calls = client.call_log[turn_start:]
        metrics = {"turn": turns, **client.context_metrics(prompt, history),
                   "input_tokens": sum(c.get("usage", {}).get("input_tokens", 0) for c in turn_calls),
                   "output_tokens": sum(c.get("usage", {}).get("output_tokens", 0) for c in turn_calls),
                   "repair_tokens": sum(c.get("usage", {}).get("total_tokens", 0) for c in turn_calls if c.get("call_type") == "repair"),
                   "repair_input_tokens": sum(c.get("usage", {}).get("input_tokens", 0) for c in turn_calls if c.get("call_type") == "repair"),
                   "repair_output_tokens": sum(c.get("usage", {}).get("output_tokens", 0) for c in turn_calls if c.get("call_type") == "repair"),
                   "accumulated_tool_result_bytes_sent": sum(size(e.get("result", e.get("verdicts", {}))) for e in history if e.get("event") in {"TOOL_RESULT", "GUARD_FEEDBACK"}),
                   "tool_result_bytes_sent": last_tool_bytes,
                   "primary_calls": sum(c.get("call_type") == "primary" for c in turn_calls),
                   "repair_calls": sum(c.get("call_type") == "repair" for c in turn_calls)}
        turn_metrics.append(metrics)
        decisions.append({"turn": turn + 1, "decision": action, "usage": call.get("usage", {})})
        event = {"event": "INVESTIGATOR_ACTION", "turn": turns, "remaining_turns": max_turns-turns, "action": action}
        context.add(event)
        full_history.append(event)
        if action["type"] == "FINISH":
            finished = True
            stop_reason = action["reason"]
            break
        if action["type"] == "TOOL_CALL":
            args = action["tool"]["arguments"]
            name = action["tool"]["name"]
            result = tools.dispatch(name, args)
            last_tool_bytes = context.observation(name, result, args)
            full_history.append({"event": "TOOL_RESULT", "tool_name": name, "result": result})
            continue
        findings = action["findings"]
        proposals.append({"turn": turn + 1, "findings": findings, "reason": action.get("reason", "")})
        guard = validate_findings(findings, tools)
        guards.append({"turn": turn + 1, **guard})
        tools.confirmed_facts.extend(guard.get("validated_facts", []))
        context.guard(guard)
        full_history.append({"event": "GUARD_FEEDBACK", "result": guard})
        last_tool_bytes = size(context.interactions[-1])
    case_calls = client.call_log[start_call_index:]
    # Failed responses also get a per-turn entry, including all bounded repairs.
    if len(turn_metrics) < turns:
        failed_calls = client.call_log[turn_start:] if "turn_start" in locals() else []
        turn_metrics.append({"turn": turns, **client.context_metrics(prompt, history if "history" in locals() else [case_event]),
            "input_tokens": sum(c.get("usage", {}).get("input_tokens", 0) for c in failed_calls),
            "output_tokens": sum(c.get("usage", {}).get("output_tokens", 0) for c in failed_calls),
            "repair_tokens": sum(c.get("usage", {}).get("total_tokens", 0) for c in failed_calls if c.get("call_type") == "repair"),
            "tool_result_bytes_sent": last_tool_bytes,
            "primary_calls": sum(c.get("call_type") == "primary" for c in failed_calls),
            "repair_calls": sum(c.get("call_type") == "repair" for c in failed_calls)})
    usage = {"model": client.model, "calls": len(case_calls),
             "input_tokens": sum(c.get("usage", {}).get("input_tokens", 0) for c in case_calls),
             "output_tokens": sum(c.get("usage", {}).get("output_tokens", 0) for c in case_calls),
             "total_tokens": sum(c.get("usage", {}).get("total_tokens", 0) for c in case_calls),
             "estimated_cost_usd": (sum(c.get("cost_usd", 0) for c in case_calls)
                                     if case_calls and all(c.get("cost_usd") is not None for c in case_calls) else None)}
    primary_calls = sum(c.get("call_type") == "primary" for c in case_calls)
    repair_calls = sum(c.get("call_type") == "repair" for c in case_calls)
    return {"stop_reason": stop_reason, "turn_metrics": turn_metrics,
            "primary_calls": primary_calls, "repair_calls": repair_calls,
            "invalid_responses": sum(bool(c.get("validation_error")) for c in case_calls),
            "successful_responses": sum(c.get("successful", False) for c in case_calls),
            "average_tokens_per_turn": usage["total_tokens"] / turns if turns else 0,
            "average_input_tokens_per_turn": usage["input_tokens"] / turns if turns else 0,
            "peak_prompt_bytes": max((c.get("prompt_context_bytes", 0) for c in case_calls), default=0),
            "peak_request_bytes": max((c.get("prompt_context_bytes", 0) + c.get("schema_bytes", 0) for c in case_calls), default=0),
            "context_compactions": context.compactions,
            "model_call_trace": case_calls,
            "fallback_reason": (stop_reason if not finished else "NO_GUARD_VALIDATED_FACTS" if not tools.confirmed_facts else ""),
            "full_history": _without_visual_bytes(full_history),
            "case_id": case_id, "turns": turns, "finished": finished,
            "tool_calls": tools.tool_log, "search_calls": tools.search_log,
            "agent_decisions": decisions, "proposed_findings": proposals,
            "guard_responses": guards, "validated_facts": tools.confirmed_facts,
             "token_usage": usage, "model_calls": sum(c.get("api_calls", 0) for c in case_calls),
            "replay_cache_miss": replay_miss, "response_invalid": response_invalid,
            "fallback_required": bool(replay_miss or response_invalid) or not finished,
            "candidate_evidence_ids": sorted(tools.allowed),
            "inspected_evidence_ids": sorted(tools.inspected),
            "evidence_cache": {eid: {"source_hash": item.get("source_hash"),
                "format": item.get("format"), "limitations": item.get("limitations", [])}
                for eid, item in tools.cache.items()}}


def run_turn_loop(*args, **kwargs):
    """Compatibility alias for callers that used the former shadow module."""
    return investigate(*args, **kwargs)
