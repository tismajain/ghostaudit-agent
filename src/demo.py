"""Synthetic-input adapter around the unchanged reasoning engine."""
from __future__ import annotations
import csv
import json
import os
import shutil
from pathlib import Path
from src.agent import investigate
from src.baseline_runtime import baseline_case
from src.evidence_cache import build_evidence_cache
from src.ingest import load, read_csv
from src.llm_client import OpenAIResponsesClient, PROMPT_VERSION, _validate_action
from src.routing import EvidenceScope, route

class SyntheticReplayClient(OpenAIResponsesClient):
    """Seed explicit demo fixtures, then exercise the real validated replay path.

    No model is contacted; the fixture is intentionally not marketed as model output.
    """
    def __init__(self, root: Path, fixture: Path):
        super().__init__(root, model="synthetic-fixture")
        self.actions = iter(json.loads(fixture.read_text())["actions"])

    def respond(self, system_prompt, history, mode="replay", max_repairs=2):
        action = _validate_action(next(self.actions))
        key, input_object = self._key(system_prompt, history)
        record = {"prompt_version": PROMPT_VERSION,
                  "response_schema": input_object["response_schema"],
                  "response": action, "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
                  "model_calls": 0, "provenance": "synthetic hand-authored demo fixture"}
        (self.cache_dir / f"{key}.json").write_text(json.dumps(record) + "\n")
        return super().respond(system_prompt, history, "replay", max_repairs)


def prepare(inputs: Path, workspace: Path):
    """Bind public demo filenames to the engine's existing table/storage contract."""
    dataset = workspace / "dataset"
    dataset.mkdir(parents=True, exist_ok=True)
    filenames = {"requests.csv": "sample_deletion_requests.csv", "identities.csv": "user_identities.csv",
                 "identity_history.csv": "user_audit_log.csv", "activity.csv": "system_activity.csv",
                 "policy.csv": "deletion_rules.csv", "evidence_manifest.csv": "evidence_files.csv"}
    for source, target in filenames.items():
        shutil.copyfile(inputs / source, dataset / target)
    shutil.copytree(inputs / "evidence", dataset / "evidence", dirs_exist_ok=True)
    data = load(workspace)
    build_evidence_cache(workspace)
    cache = {p.name.removesuffix("_normalized.json"): json.loads(p.read_text())
             for p in (workspace / "cache/evidence_v2").glob("*_normalized.json")}
    scope = EvidenceScope(workspace, data, cache)
    request = data["sample_deletion_requests"][0]
    baseline = baseline_case(request, data, {})
    evidence_ids = scope.for_case(request, baseline["resolved_identity"], baseline["facts"])
    baseline["candidate_evidence_ids"] = evidence_ids
    routing = route(baseline, evidence_ids, scope.manifest)
    storage = workspace / "baseline"
    traces = storage / "dev_traces"
    traces.mkdir(parents=True, exist_ok=True)
    (traces / f"{request['case_id']}.json").write_text(json.dumps(baseline, indent=2) + "\n")
    prediction = {"case_id": request["case_id"], "deletion_status": baseline["final_status"],
                  "steps_json": json.dumps(baseline["generated_steps"], separators=(",", ":"))}
    with (storage / "dev_predictions.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(prediction))
        writer.writeheader()
        writer.writerow(prediction)
    return data, baseline, routing, storage, prediction


def run_demo(root: Path, output: Path, mode: str = "replay"):
    output.mkdir(parents=True, exist_ok=True)
    workspace = output / "workspace"
    data, baseline, routing, storage, prediction = prepare(root / "examples/demo", workspace)
    trace = None
    effective = mode
    if mode == "live" and not os.environ.get("OPENAI_API_KEY"):
        effective = "deterministic"
    if effective == "replay":
        client = SyntheticReplayClient(workspace, root / "examples/replay/investigation.json")
        trace = investigate(workspace, prediction["case_id"], data, mode="replay",
                            baseline_dir=storage, client=client, max_turns=8)
    elif effective == "live":
        client = OpenAIResponsesClient(workspace, model="gpt-4.1-mini")
        trace = investigate(workspace, prediction["case_id"], data, mode="live",
                            baseline_dir=storage, client=client, max_turns=8)
    verdicts = [v["status"] for g in (trace or {}).get("guard_responses", []) for v in g["results"]]
    # Preserve the measured system's closed promotion gate: agent facts are diagnostic.
    result = {"case_id": prediction["case_id"], "status": prediction["deletion_status"],
              "resolved_subject": baseline["resolved_identity"]["user_id"],
              "request_used_historical_email": baseline["request"]["email"] != baseline["resolved_identity"]["current_identifiers"]["email"],
              "steps": json.loads(prediction["steps_json"]), "mode": effective,
              "replay_provenance": "hand-authored synthetic fixture" if effective == "replay" else None,
              "real_model_calls": (trace or {}).get("model_calls", 0),
              "tool_calls": len((trace or {}).get("tool_calls", [])),
              "guard_verdicts": verdicts, "routing": routing,
              "agent_prediction_promotion": False, "trace": trace}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
