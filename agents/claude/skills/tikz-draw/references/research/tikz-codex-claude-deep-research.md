# Deep Research: Making Codex and Claude Generate Better, More Structural TikZ

Date: 2026-04-19

## Scope

This report is limited to trusted primary sources:

- Official OpenAI / Codex documentation
- Official Anthropic / Claude documentation
- The PGF/TikZ manual

Excluded by design:

- Community blog posts
- Reddit / forum advice
- Unofficial prompt recipes without primary-source backing

Focus:

- Reusable skills and durable guidance for Codex / Claude
- Model settings that affect structural diagram generation
- TikZ features that support structural layouts better than raw coordinate drawing

## Coverage

Inspected evidence classes:

- Codex guidance-discovery docs, config docs, prompt-engineering docs, structured-output docs, prompt-guidance docs, and skills best-practices docs
- Anthropic prompting docs, effort / extended-thinking docs, structured-output docs, and Agent Skills docs
- PGF/TikZ manual sections on nodes, positioning, matrices, fit, graphs, and graph drawing

Within that scope, this is a complete analysis.

## Executive Summary

The strongest cross-vendor pattern is this: if you want better TikZ, do not ask the model to jump straight from prose to final drawing code. Ask it to produce a structural intermediate representation first, then render TikZ from that representation. This recommendation is supported by OpenAI Structured Outputs, Anthropic Structured Outputs, OpenAI guidance on Markdown/XML prompt structure, Anthropic guidance on XML tags, and the PGF/TikZ manual's own emphasis on structural libraries such as `positioning`, `matrix`, `fit`, `graphs`, and `graphdrawing` rather than manual coordinate placement. [S4][S5][S8][S10][S13][S14][S15]

For Codex specifically, OpenAI's documentation points toward durable guidance in `AGENTS.md` and repeatable workflows packaged as Skills rather than oversized one-off prompts. For Claude, Anthropic's docs make the same general move: Skills are reusable, filesystem-based expertise, only their metadata is preloaded, and the full `SKILL.md` is loaded only when relevant. [S1][S7][S11][S12]

## Key Findings

### 1. Durable guidance beats giant one-off prompts

**Observation.** Codex builds an instruction chain from global and project `AGENTS.md` files, with closer files overriding earlier guidance, and the total combined size is capped by `project_doc_max_bytes` by default. [S1] OpenAI also explicitly warns against overloading prompts with durable rules instead of moving them into `AGENTS.md` or a skill, and says repeatable workflows should be packaged as Skills. [S7]

**Observation.** Anthropic describes Skills as reusable, filesystem-based expertise that turns a general-purpose agent into a specialist; only skill metadata is discovered at startup, while full content is loaded when triggered. Anthropic's skill best-practices page also stresses that good Skills should be concise and well-structured because they still compete for context once loaded. [S11][S12]

**Inference.** For recurring TikZ work, a dedicated structural-diagram skill is a better long-run control surface than repeatedly pasting large prompts.

**Recommendation.** Create one narrowly scoped skill such as `tikz-structural-diagrams` whose job is:

- classify the diagram family
- choose the structural TikZ libraries
- emit an intermediate structural spec
- emit final TikZ code
- self-check that the output uses structure, not unnecessary absolute coordinates

### 2. Structured outputs are the best foundation for structural TikZ

**Observation.** OpenAI Structured Outputs ensures adherence to a supplied JSON Schema and is recommended over older JSON mode when possible. OpenAI also notes that if mistakes remain, you should improve instructions, provide examples, or split tasks into simpler subtasks. [S5]

**Observation.** Anthropic Structured Outputs works by defining a JSON Schema, passing `output_config.format` with `type: "json_schema"`, and then parsing a response that is valid JSON matching that schema. [S10]

**Observation.** OpenAI recommends using Markdown and XML tags to separate Identity, Instructions, Examples, and Context in developer messages. Anthropic says XML tags help Claude parse complex prompts unambiguously and reduce misinterpretation when prompts mix instructions, context, examples, and inputs. [S4][S8]

**Inference.** The most reliable workflow is a two-pass pipeline:

1. Generate a diagram spec in JSON or XML.
2. Generate TikZ from that spec.

**Recommendation.** Use an intermediate schema with fields like:

```json
{
  "diagram_type": "block-diagram | layered-graph | tree | matrix | automaton | flowchart",
  "tikz_libraries": ["positioning", "fit"],
  "styles": {
    "node": "draw, rounded corners, align=center",
    "edge": "->"
  },
  "nodes": [
    {
      "id": "parser",
      "label": "Parser",
      "style": "node",
      "placement": { "relation": "right=of", "target": "input" }
    }
  ],
  "edges": [
    { "from": "input", "to": "parser", "style": "edge", "label": "" }
  ],
  "groups": [
    { "id": "frontend", "members": ["input", "parser"], "fit_style": "draw, dashed" }
  ],
  "constraints": [
    "Prefer relative placement over absolute coordinates"
  ]
}
```

That schema is a synthesized recommendation, not a vendor-prescribed schema, but it follows the control mechanisms both vendors officially recommend. [S4][S5][S8][S10]

### 3. For Codex, use settings after you tighten the prompt contract

**Observation.** Codex exposes `model_reasoning_effort`, `model_verbosity`, `model_instructions_file`, `skills.config`, and `project_doc_max_bytes` in `config.toml`. [S2]

**Observation.** OpenAI says verbosity is configurable as `low`, `medium`, or `high`, and with GPT-5.4, `medium` and `high` produce longer, more structured code with inline explanations. [S3]

**Observation.** OpenAI's prompt-guidance docs say reasoning effort is a "last-mile knob," not the primary way to improve quality; before raising it, teams should strengthen prompts, output contracts, and lightweight verification loops. For research-heavy work, OpenAI recommends starting at `medium` or higher. [S6]

**Inference.** For structural TikZ generation in Codex, the first levers should be:

- durable instructions in `AGENTS.md` or a Skill
- a strict structural schema
- a prompt layout with Identity / Instructions / Examples / Context

Only after that should you raise reasoning effort.

**Recommendation.** For Codex / GPT-5.4:

- Start with `model_verbosity = "high"` for nontrivial TikZ generation.
- Start with `model_reasoning_effort = "medium"` when the task is mostly diagram transcription or straightforward layout conversion.
- Raise to `high` when the task includes multi-cluster layout choices, refactoring brittle coordinate-heavy TikZ into structural TikZ, or reconciling many placement constraints.
- Do not use higher reasoning as the first fix for weak output; first tighten the intermediate schema and prompt sections. [S2][S3][S4][S6]

### 4. For Claude, effort and XML structure matter more than vague prompting

**Observation.** Anthropic's prompting guide says Claude responds well to clear, explicit instructions; examples are one of the most reliable ways to steer structure; and XML tags reduce misinterpretation for mixed prompts. [S8]

**Observation.** Anthropic's Opus 4.7 best-practices guidance recommends `xhigh` effort for most coding and agentic use cases and at least `high` effort for most intelligence-sensitive use cases. It also says that if complex tasks look shallow, the first lever is to raise effort. [S8]

**Observation.** Anthropic's extended-thinking docs say extended thinking gives Claude enhanced reasoning capabilities for complex tasks, and that larger budgets can improve response quality by enabling more thorough analysis for complex problems. [S9]

**Inference.** Claude is likely to benefit when structural TikZ work is framed explicitly as a coding-plus-layout task with:

- XML-separated prompt sections
- success criteria
- examples of desired structural output
- higher effort / adaptive thinking for genuinely hard cases

**Recommendation.** If your Claude surface exposes effort or adaptive / extended thinking:

- Use `high` as the interactive baseline for serious TikZ work.
- Use `xhigh` for the hardest structural cases if you are optimizing for quality over latency, which is consistent with Anthropic's Opus 4.7 coding guidance. [S8]
- Reserve lower effort for simple one-shot edits or tiny diagram patches.
- Keep the prompt strongly structured with tags such as `<diagram_task>`, `<constraints>`, `<examples>`, and `<output_contract>`. [S8][S9][S10]

### 5. The PGF/TikZ manual strongly favors structural layout tools

**Observation.** In the manual's nodes section, TikZ nodes can be named and referenced later; the positioning library adds more convenient placement options, and for larger arrangements the manual explicitly points readers to the matrix and graphdrawing libraries. [S13]

**Observation.** The matrices section says matrices are often a simpler way to solve alignment problems and that cell sizes are automatically adjusted to fit contents. [S14]

**Observation.** The fit library computes a minimal bounding box around coordinates or nodes and sets text width, `align=center`, and `anchor=center`, which makes it well-suited for grouping and enclosure. [S13]

**Observation.** The graphs section says the `\graph` command offers a concise and powerful way to specify which nodes are present and how they are connected. The graph-drawing section says graph drawing algorithms do the hard work of computing graph layouts. [S15]

**Inference.** Models should be instructed to choose the layout mechanism by diagram type instead of defaulting to raw `(x,y)` coordinates.

**Recommendation.** Tell Codex / Claude to prefer:

- `positioning` for small and medium dependency / block diagrams
- `matrix` for aligned grids, layered tables, or repeated column / row structures
- `fit` for group boxes, highlighted subsystems, or enclosing related nodes
- `graphs` for explicit graph syntax
- `graphdrawing` for trees, layered DAGs, circular graphs, and other auto-layout-heavy diagrams
- absolute coordinates only when the geometry itself is the content

## Recommended Skill Design

### Codex skill

**Why this follows the docs.** OpenAI says repeatable workflows should become Skills and durable rules should move out of giant prompts into `AGENTS.md` or skills. [S1][S7]

Suggested skill scope:

- One job only: structural TikZ generation and refactoring
- Trigger phrases:
  - "draw this in TikZ"
  - "convert this diagram to TikZ"
  - "make this TikZ more structural"
  - "replace coordinates with positioning / matrix / fit"
- Required behavior:
  1. classify the diagram type
  2. choose libraries before writing code
  3. generate a structural spec first
  4. generate compile-ready TikZ second
  5. explain any forced use of absolute coordinates

Suggested durable guidance for `AGENTS.md` or the skill body:

- Prefer `positioning`, `matrix`, `fit`, `graphs`, and `graphdrawing` over manual coordinates when possible.
- Name nodes semantically.
- Centralize shared styles in `\tikzset` or `every node/.style` rather than repeating long inline option lists.
- Use `fit` for subsystem grouping.
- Use matrices for row / column alignment.
- If the requested output is complex, emit a structural spec first and only then emit TikZ.

### Claude skill

**Why this follows the docs.** Anthropic says Skills are reusable filesystem-based expertise, only metadata is preloaded, and good skills must be concise, well-structured, and tested with real usage. [S11][S12]

Suggested skill frontmatter:

```yaml
---
name: tikz-structural-diagrams
description: Generate or refactor TikZ diagrams using structural layout libraries such as positioning, matrix, fit, graphs, and graphdrawing. Use when asked to create maintainable TikZ/PGF code rather than coordinate-heavy sketches.
---
```

Suggested body sections:

- `## When to use this skill`
- `## Diagram classification`
- `## Library selection rules`
- `## Output contract`
- `## Examples`

The skill should stay concise and avoid teaching Claude generic TeX knowledge it likely already has. That is directly aligned with Anthropic's guidance to only add context Claude does not already know. [S11]

## Recommended Prompt Contracts

### Shared contract

This is a synthesized template based on the vendor docs, not a direct quote:

```xml
<diagram_task>
Produce maintainable TikZ, not just visually plausible TikZ.
</diagram_task>

<constraints>
- Prefer structural libraries over absolute coordinates.
- Name nodes semantically.
- Reuse styles instead of repeating inline options.
- If a matrix, layered graph, or grouping structure is present, model it explicitly.
</constraints>

<output_contract>
1. Emit a structural diagram specification.
2. Emit the final TikZ code.
3. Briefly justify the chosen TikZ libraries.
</output_contract>

<success_criteria>
- Relative placement is used where possible.
- Grouping uses fit/background mechanisms when needed.
- Grids and aligned blocks use matrices where appropriate.
- Dense graph connectivity uses graphs/graphdrawing where appropriate.
- Absolute coordinates appear only when justified.
</success_criteria>
```

Why this is evidence-backed:

- OpenAI recommends Markdown/XML sectioning and explicit prompt sections. [S4]
- Anthropic recommends XML tags, clear instructions, and examples. [S8]
- Structured Outputs from both vendors support first-pass schema generation. [S5][S10]
- The TikZ manual supports choosing structural libraries based on layout needs. [S13][S14][S15]

## Bottom-Line Recommendations

If the goal is "better and more structural TikZ," the best practical stack is:

1. Put persistent TikZ rules into a dedicated skill or durable instructions, not repeated ad hoc prompts. [S1][S7][S11][S12]
2. Require an intermediate JSON or XML diagram spec before final TikZ. [S4][S5][S8][S10]
3. In Codex, start with stronger output contracts plus `high` verbosity, then raise reasoning only when the structure is genuinely hard. [S2][S3][S6]
4. In Claude, use XML-tagged prompts and `high` or `xhigh` effort for serious structural diagrams if that control is available. [S8][S9]
5. Tell the model exactly which TikZ structural tools to prefer by diagram type: `positioning`, `matrix`, `fit`, `graphs`, `graphdrawing`. [S13][S14][S15]

## Sources

- **S1** `[NOT_A_PAPER]` OpenAI, "How Codex discovers guidance." Official Codex docs. Key evidence: instruction-chain precedence, `AGENTS.md` discovery, override order, and `project_doc_max_bytes`.  
  https://developers.openai.com/codex/guides/agents-md#how-codex-discovers-guidance

- **S2** `[NOT_A_PAPER]` OpenAI, "Codex config reference." Official Codex docs. Key evidence: `model_reasoning_effort`, `model_verbosity`, `skills.config`, `model_instructions_file`, `project_doc_max_bytes`.  
  https://developers.openai.com/codex/config-reference#configtoml

- **S3** `[NOT_A_PAPER]` OpenAI, "Using GPT-5.4" / verbosity section. Key evidence: `medium` and `high` verbosity yield longer, more structured code.  
  https://developers.openai.com/api/docs/guides/latest-model#verbosity

- **S4** `[NOT_A_PAPER]` OpenAI, "Prompt engineering" / Markdown and XML section. Key evidence: use Markdown and XML to separate Identity, Instructions, Examples, and Context.  
  https://developers.openai.com/api/docs/guides/prompt-engineering#message-formatting-with-markdown-and-xml

- **S5** `[NOT_A_PAPER]` OpenAI, "Structured model outputs." Key evidence: schema adherence, reliable typing, explicit refusals, and recommendation to split tasks / improve instructions if mistakes remain.  
  https://developers.openai.com/api/docs/guides/structured-outputs

- **S6** `[NOT_A_PAPER]` OpenAI, "Prompt guidance for GPT-5.4" / reasoning-effort section. Key evidence: reasoning effort is a last-mile knob; strengthen output contracts before raising it.  
  https://developers.openai.com/api/docs/guides/prompt-guidance#treat-reasoning-effort-as-a-last-mile-knob

- **S7** `[NOT_A_PAPER]` OpenAI, "Codex best practices." Key evidence: use skills for repeatable work; avoid overloading prompts with durable rules instead of moving them into `AGENTS.md` or a skill.  
  https://developers.openai.com/codex/learn/best-practices#turn-repeatable-work-into-skills  
  https://developers.openai.com/codex/learn/best-practices#common-mistakes

- **S8** `[NOT_A_PAPER]` Anthropic, "Prompting best practices." Key evidence: clear and direct instructions, effective examples, XML tags reduce misinterpretation, and Opus 4.7 effort guidance for coding / agentic work.  
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices

- **S9** `[NOT_A_PAPER]` Anthropic, "Building with extended thinking." Key evidence: enhanced reasoning for complex tasks; larger thinking budgets can improve quality on complex problems.  
  https://platform.claude.com/docs/en/build-with-claude/extended-thinking

- **S10** `[NOT_A_PAPER]` Anthropic, "Structured outputs." Key evidence: define JSON schema, pass `output_config.format`, parse valid JSON matching the schema.  
  https://platform.claude.com/docs/en/build-with-claude/structured-outputs

- **S11** `[NOT_A_PAPER]` Anthropic, "Skill authoring best practices." Key evidence: skills should be concise, well-structured, and context-efficient.  
  https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

- **S12** `[NOT_A_PAPER]` Anthropic, "Agent Skills in the SDK." Key evidence: skills are `SKILL.md` filesystem artifacts; metadata is discovered at startup and full content loads when triggered.  
  https://code.claude.com/docs/en/agent-sdk/skills

- **S13** `[NOT_A_PAPER]` PGF/TikZ Manual, "Nodes and Edges." Key evidence: named nodes, positioning library, larger-node arrangements pointing to matrix and graphdrawing libraries, and `fit`-based enclosure.  
  HTML manual: https://tikz.dev/tikz-shapes  
  Official PDF manual: https://pgf-tikz.github.io/pgf/pgfmanual.pdf

- **S14** `[NOT_A_PAPER]` PGF/TikZ Manual, "Matrices and Alignment." Key evidence: matrices simplify alignment and auto-adjust cell sizes.  
  HTML manual: https://tikz.dev/tikz-matrices  
  Official PDF manual: https://pgf-tikz.github.io/pgf/pgfmanual.pdf

- **S15** `[NOT_A_PAPER]` PGF/TikZ Manual, "Specifying Graphs" and "Graph Drawing." Key evidence: `\graph` is a concise, powerful graph specification mechanism and graph-drawing algorithms compute layouts automatically.  
  HTML manual: https://tikz.dev/tikz-graphs  
  HTML manual: https://tikz.dev/gd  
  Official PDF manual: https://pgf-tikz.github.io/pgf/pgfmanual.pdf
