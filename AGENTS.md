# Agent ownership and compatibility

These boundaries apply before implementing the staged agent-DAST goals.

- `src/agent-dast/loop/` and `src/agent-dast/providers/` are Codex-owned.
- `src/agent-dast/eval/` and `benchmarks/agent-eval/` are Claude-owned: Codex may import them but must not modify them.
- Do not break public signatures of `runExecutionPlan` (`src/agent-dast/runner.ts`) or `RunStore` (`src/agent-dast/store.ts`). Add a new function if a new contract is required.

Other existing agent-DAST orchestration files remain Claude-owned. Goal-specific file restrictions take precedence over general ownership. Do not modify runner.ts or store.ts for G1/G2.

G1/G2 use offline agents, replay and mocked engines by default. Actual model calls require explicit live opt-in; actual target traffic for G3/G4 additionally requires owner authorization and a recorded target scope. Keep raw responses, credentials and evidence bodies out of agent inputs, transcripts and logs.
