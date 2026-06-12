# Plan

## Phases

1. Finalize the shared execution contract.
   - Lock the helper API, absolute-path rules, run-root rules, `figure-brief.json` contract, and canonical source-of-truth layout.
2. Build the shared assets.
   - Create schema files, snippet inventory, style files, and prevention/review rule assets in the task workspace.
3. Implement Codex `tikz-draw`.
   - Add the root skill, runtime helper, references, routing updates, and deep-research handoff changes.
4. Implement Claude `/tikz`.
   - Add the private skill, public command, command-style docs, routing updates, and deep-research handoff changes.
5. Verify both platforms.
   - Run wiring checks, wrapper-based smoke tests, and one end-to-end research-to-TikZ scenario per platform.

## Dependencies

- Shared schema and path contract must be defined before either platform helper is implemented.
- Codex frontmatter and Claude command/frontmatter policy must be fixed before trigger/routing verification.
- Deep-research template updates depend on the final `figure-brief.json` contract and artifact-path rules.
- End-to-end verification depends on the helper API being identical across both platforms.

## Risks

- Risk: wrapper cwd and path handling cause outputs to land in the wrong place.
  - Mitigation: normalize to absolute host paths and create output roots explicitly in the helpers.
- Risk: Codex trigger reliability is poor because the skill description is too weak.
  - Mitigation: design frontmatter first, then validate against multiple prompt shapes.
- Risk: Claude registration becomes ambiguous because both a command and a public skill appear.
  - Mitigation: make `/tikz` public and the skill private via frontmatter.
- Risk: deep-research integration becomes documentation-only and not executable.
  - Mitigation: require `figure-brief.json`, artifact directories, and explicit reader/writer ownership.
- Risk: shared assets drift between task workspace, Codex, and Claude trees.
  - Mitigation: enforce one canonical source tree and a deliberate install/copy step.

## Verification checkpoints

- After phase 1:
  - helper API is consistent everywhere
  - run-root and `figure-brief` contracts are documented concretely
- After phase 2:
  - shared schemas and assets exist in the canonical source tree
- After phase 3:
  - Codex skill validates structurally and the runtime helper passes `doctor`
- After phase 4:
  - Claude `/tikz` wiring is correct and the private skill is not publicly duplicated
- After phase 5:
  - both wrappers pass smoke tests
  - both deep-research workflows can hand off a figure brief and record artifacts
