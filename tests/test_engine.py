"""Behavioral checks on new synthetic inputs; no private benchmark dependencies."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.agent import investigate
from src.agent_tools import AgentTools, validate_tool_arguments
from src.demo import prepare, run_demo, SyntheticReplayClient
from src.guard import validate_findings
from src.identity import resolve
from src.llm_client import OpenAIResponsesClient, ActionValidationError, ModelResponseInvalid, _validate_action
from src.schemas import step_key

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = json.loads((ROOT / "examples/replay/investigation.json").read_text())["actions"]
NETWORK = None

def setUpModule():
    global NETWORK
    NETWORK = patch("urllib.request.urlopen", side_effect=AssertionError("Tests must never use the network"))
    NETWORK.mock = NETWORK.start()

def tearDownModule():
    try:
        NETWORK.mock.assert_not_called()
    finally:
        NETWORK.stop()

class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.temp.name)
        cls.data, cls.baseline, cls.routing, cls.storage, cls.prediction = prepare(ROOT / "examples/demo", cls.workspace)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def tools(self):
        t = AgentTools(self.workspace, "case_81001", self.data, self.storage)
        t.list_candidate_evidence("case_81001")
        t.inspect_evidence("evidence_81002", "search_81002")
        return t

    def test_disjoint_valid_action_branches(self):
        for action in (ACTIONS[0], ACTIONS[2], ACTIONS[-1]):
            self.assertEqual(_validate_action(action), action)

    def test_combined_actions_and_extra_fields_are_rejected(self):
        for action, extra in ((ACTIONS[0], {"findings": []}), (ACTIONS[2], {"tool": {}}), (ACTIONS[-1], {"findings": []})):
            with self.subTest(action=action["type"]), self.assertRaises(ActionValidationError):
                _validate_action({**action, **extra})

    def test_tool_arguments_are_native_and_allowlisted(self):
        with self.assertRaises(ValueError):
            validate_tool_arguments("shell", {"command": "ignored"})
        with self.assertRaises(ValueError):
            validate_tool_arguments("inspect_evidence", "{}")
        with self.assertRaises(ValueError):
            validate_tool_arguments("inspect_evidence", {})

    def test_guard_confirms_atomic_grounding(self):
        result = validate_findings(ACTIONS[2]["findings"], self.tools())
        self.assertEqual(result["results"][0]["status"], "CONFIRMED")
        self.assertEqual(result["validated_facts"][0]["state"], "PRESENT")

    def test_guard_rejects_a_false_state(self):
        finding = copy.deepcopy(ACTIONS[2]["findings"])
        finding[0]["state"] = "ABSENT"
        self.assertEqual(validate_findings(finding, self.tools())["results"][0]["status"], "REJECTED")

    def test_whole_file_proximity_is_not_ownership(self):
        t = self.tools()
        t.trace = copy.deepcopy(t.trace)
        t.trace["facts"] = []
        t.data = copy.deepcopy(t.data)
        unit = next(u for u in t.data["units"] if u["resource_id"] == "search_81002")
        unit["data"] = {"resource_id": "search_81002", "user_id": "user_99999", "result": "PRESENT"}
        unit["text"] = "privacy.old@example.test appears in a different document section"
        t.data["units"] = [unit]
        t.data["system_activity"] = []
        self.assertEqual(validate_findings(ACTIONS[2]["findings"], t)["results"][0]["status"], "UNVERIFIABLE")

    def test_history_resolves_old_email_without_fuzzy_matching(self):
        identity = self.baseline["resolved_identity"]
        self.assertEqual(identity["user_id"], "user_81001")
        self.assertIn("privacy.old@example.test", identity["search_identifiers"])
        self.assertIn("privacy@example.test", identity["search_identifiers"])
        request = dict(self.baseline["request"], email="privacy.old+tag@example.test")
        self.assertIsNone(resolve(request, self.data["user_identities"], self.data["user_audit_log"])["user_id"])

    def test_post_audit_evidence_is_not_eligible(self):
        t = self.tools()
        self.assertNotIn("evidence_81004", t.manifest)
        self.assertTrue(t.dispatch("inspect_evidence", {"evidence_id": "evidence_81004"})["denied"])
        self.assertNotIn("evidence_81004", {s["evidence_id"] for s in self.baseline["generated_steps"]})

    def test_sync_disabled_before_dependent_copy_deletion(self):
        steps = self.baseline["generated_steps"]
        operations = [s["operation"] for s in steps]
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", operations)
        self.assertLess(operations.index("DISABLE_DATA_FLOW"), operations.index("DELETE_RECORD"))
        self.assertEqual(steps, sorted(steps, key=step_key))
        self.assertEqual([s["step_no"] for s in steps], list(range(1, len(steps) + 1)))

    def test_injected_business_text_does_not_override_baseline(self):
        self.assertEqual(self.baseline["final_status"], "INCOMPLETE")
        self.assertIn("search_81002", {s["resource_id"] for s in self.baseline["generated_steps"]})

    def test_fixture_replay_runs_tools_and_guard_without_api_calls(self):
        client = SyntheticReplayClient(self.workspace, ROOT / "examples/replay/investigation.json")
        trace = investigate(self.workspace, "case_81001", self.data, mode="replay", baseline_dir=self.storage, client=client)
        self.assertTrue(trace["finished"])
        self.assertEqual(trace["model_calls"], 0)
        self.assertEqual(len(trace["tool_calls"]), 3)
        self.assertEqual(len(trace["guard_responses"]), 2)
        self.assertEqual(client.usage_summary()["replay_cache_hits"], 6)

    def test_no_key_live_request_falls_back_and_matches_replay_steps(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            result = run_demo(ROOT, Path(tmp), "live")
        self.assertEqual(result["mode"], "deterministic")
        self.assertEqual(result["real_model_calls"], 0)
        self.assertEqual(result["steps"], self.baseline["generated_steps"])

    def test_native_replay_cache_rejects_missing_responses(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = OpenAIResponsesClient(Path(tmp))
            with self.assertRaises(KeyError):
                client.respond("system", [{"event": "CASE"}], "replay")

    def test_bounded_repair_success_and_exhaustion(self):
        class Scripted(OpenAIResponsesClient):
            def __init__(self, root, responses):
                super().__init__(root)
                self.responses = iter(responses)
            def _request_live(self, system, history, key):
                return next(self.responses), {"mode": "live", "api_calls": 0, "usage": {}, "cache_key": key}, "synthetic-test"
        good = json.dumps({"action": ACTIONS[-1]})
        with tempfile.TemporaryDirectory() as tmp:
            client = Scripted(Path(tmp), ["bad", good])
            action, call = client.respond("system", [], "live")
            self.assertEqual(action["type"], "FINISH")
            self.assertEqual(call["repair_count"], 1)
            client = Scripted(Path(tmp), ["bad"] * 3)
            with self.assertRaises(ModelResponseInvalid):
                client.respond("system", [], "live")
            self.assertEqual(len(client.call_log), 3)

if __name__ == "__main__":
    unittest.main()
