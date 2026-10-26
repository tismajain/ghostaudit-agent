# Decision authority and evidence flow

GhostAudit separates investigation from decision authority. `agent.py` chooses actions through the LLM client; `agent_tools.py` exposes a bounded evidence interface; `guard.py` independently validates claims. `identity.py`, `state.py`, `policy.py` and `planner.py` own identity lineage, observations, policy treatment and ordered output. The model cannot emit final answer rows.

## The loop

The wire response contains one `action` with a nested strict union: TOOL_CALL, PROPOSE_FINDINGS or FINISH. Unknown/overlapping fields are rejected. Repair attempts are bounded and counted separately from investigation turns. Guard CONFIRMED, REJECTED and UNVERIFIABLE verdicts return to the loop, allowing further investigation without automatic acceptance or finish.

`agent_context.py` separates complete local traces from model context. Typed observations bound record/span sizes, expose pagination and deduplicate repeated observations. History compaction preserves confirmed facts, rejected hypotheses, unresolved questions and inspected resources/evidence, retaining recent interactions. Hard limits stop safely rather than silently fabricate missing context.

## Guard semantics

A proposed resource must have a literal ID in inspected, eligible evidence. Ownership requires an exact non-collided subject anchor in the same atomic record or an independently grounded explicit relationship chain. Whole-file proximity is discovery, not proof. Claimed state/category and literal fields are re-derived, not trusted because the model repeats them.

Capture time and observation time must be at or before `audit_at`. Later evidence cannot retroactively prove the earlier state. Workflow COMPLETE/SUCCESS remains a claim; known LOW best-effort assumptions are disclosed, not recast as direct evidence.

## Routing and fallback

Routing is driven by LOW-confidence steps, unresolved resources, case-scoped binary evidence, or low-confidence request wording. A global PDF/PNG file does not by itself route unrelated people. The final measured prediction-promotion gate stayed closed because the agent did not improve the public metrics.

The public adapter preserves that authority: replay/live findings are diagnostic and the baseline owns the final row. API failure, timeout, invalid output, missing key or exhausted turns never require a blank result. This is not an engine for executing deletion operations.

## Public adapter versus original engine

`demo.py` binds new synthetic files to the existing table contract in an ignored local workspace. The compatibility filenames inside that generated workspace are implementation details, not private benchmark requirements. The core agent, guard and reasoning modules are preserved; only imports for extracted request-intent helpers were redirected. No competition annotations, case-ID routing lists, batch outputs or promotion configuration were copied.

The default action fixture is deliberately hand-authored and labeled synthetic. It seeds the normal cache envelope and exercises the real response validator/replay path, tools and guard. Live mode instead calls OpenAI through the unchanged client. See `engine_provenance.md` for copy/import checks.
