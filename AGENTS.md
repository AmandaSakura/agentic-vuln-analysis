# Development rules

- Read `docs/TEST_CONTRACT.md` before changing detection, validation, evaluation or live transport.
- Every code change must pass the complete `uv run --no-sync pytest` suite before any real model API experiment. A targeted test pass is insufficient.
- Real model calls must go through `OpenAICompatibleChatModel` and its pytest gate. Do not bypass the gate, use a saved pass stamp, add a bypass environment variable, or issue raw model HTTP requests from experiment scripts.
- Tests must be offline. Use scripted models or mocked HTTP responses; local project-owned loopback fixture tests are permitted. Never load API credentials for pytest.
- Add a regression test for each demonstrated semantic bug and include positive controls. Do not weaken assertions or blanket-return unresolved just to make the suite pass.
- Static pattern/may-flow evidence is not candidate vulnerability confirmation. Confirming evidence must bind to the exact candidate and source contents. Unsupported semantics remain unresolved, never safe.
- Development and oracle-seeded data cannot support held-out claims. Keep label mappings out of detector prompts, including IDs and path aliases.
- Preserve existing dirty changes and historical experiment artifacts. Log each actual API request and all reported usage, including failed response parsing.
