# Engine provenance and preservation

This portfolio export was made as a separate directory, without changing the measured competition checkout. No original Git metadata or challenge-provided documents/data were copied.

## Preserved reasoning modules

The following modules were byte-identical to the measured final engine at export time:

| Module | SHA-256 |
|---|---|
| `src/agent.py` | `7deffb0e986bdada0cb20f39e4f398cb35742ce0edc8a8a9f5ccf436b1e2d7b7` |
| `src/agent_context.py` | `8e05648efef1e5ef67aa9296f93280893af81d66a70929c631e6ebed77706830` |
| `src/agent_tools.py` | `184c1b46cceadf458c51f372ca537d5668c051b717cf1505270836c1ae3ab389` |
| `src/best_effort.py` | `05576f1e2468f585306208580c55cf14dddc1a638526464dd23f70bf34eddcbc` |
| `src/evidence_cache.py` | `faab138b619113772b0d1d3eef5f9308c60a975f440ed4d14865d1ec8eda5b61` |
| `src/guard.py` | `77f16dd27116bc2202567ca2e18579d68040b29be42c24d214ce9cf5bc3af5ac` |
| `src/identity.py` | `f5c0a1834f5ab2e6aaf5b6f0f9c4a9211950318eff25b9601a73a283488295c1` |
| `src/ingest.py` | `d3af3bbe856acc8026575837a0289ad9fed531f4e72d6ac49e9849752a5597b1` |
| `src/llm_client.py` | `55d8f5199c21cfa1fb78b646dd1a314f3a2d0b8701a73cc159f1ca706ebfc7d9` |
| `src/planner.py` | `d129c9d4b5953a1e76cf37e06836e6da345679c8f3522268d75657fb6cdde16e` |
| `src/policy.py` | `516e662c5d51b957894aecdf0cc13a65a9499678b273e12d039df2dd265a3cb7` |
| `src/schemas.py` | `2f440ecdb8af723e28f7d6d4e21401d42fa6a828cc891ea6d9fe4655371d063f` |
| `src/state.py` | `8044215c79a40cbb0ff06ee99bcd34f90547ed9d5c4327d4fff3a385933ea970` |
| `src/temporal.py` | `d2c682207ee6fcb37c76d7f2dc979c1b872f201560827e2e61f1ac90f064a220` |

The investigator system prompt is also byte-identical. `baseline_runtime.py` and `routing.py` change only imports to relocated request-intent helpers. The extracted intent functions were compared by Python AST and are structurally identical. No identity, state, guard, policy, ordering, action-schema, context or fallback rule was altered to improve presentation.

## Adapter-only changes

`src/demo.py` and `scripts/run_demo.py` are new synthetic-input adapters. They create an ignored workspace in the existing storage/table schema, use no private annotations, and preserve the closed promotion gate. `SyntheticReplayClient` is explicitly a new hand-authored fixture seeder around the real cache/replay validator; it does not impersonate a provider transcript. The competition-specific 518-case batch runner and annotations are not exported.

Preserving implementation does not establish publication rights. See licensing.md before publishing.
