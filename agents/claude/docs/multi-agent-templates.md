# Multi-agent research templates

When the user requests a multi-agent discussion, panel review, proof stress-test, or structured research session, read `~/.claude/skills/agent-group-discuss/EXECUTION.md` for execution instructions. Template definitions (roles, rounds, hard rules): `~/.claude/skills/agent-group-discuss/TEMPLATES.md`.

| Template | Trigger phrases | Roles | Model tier |
|----------|----------------|-------|------------|
| Lakatos Proof & Refutation | "verify proof", "stress-test", "find holes" | Prover, Counterexample Hunter, Monster-Barrer, Formalist | math-heavy (opus) |
| Polya Multi-Strategy | "attack problem", "explore complexity", "open problem" | Specializer, Generalizer, Reducer | premium (opus+sonnet) |
| Knuth Manuscript Review | "review draft", "pre-submission", "camera-ready" | Correctness, Exposition, Literature | premium (opus+sonnet) |
| Structured Research Team | General math/TCS claim verification | Builder, Breaker, Alt Builder, Referee | math-heavy (opus) |
| Graph Reconfig Specialist | Token sliding/jumping, PSPACE, gadgets | Constructor, Adversary, Auditor, Referee | math-heavy (opus) |
| Lean Formalization Team | "formalize lemma", "Lean proof", "fix sorry" | Planner, Formalizer, Miner, Repair, Checker | math-heavy (opus+sonnet) |

Execution: use Claude Code Agent tool for each role (parallel within rounds, sequential between rounds). State files: `~/.claude/data/runs/<run_id>/`.
