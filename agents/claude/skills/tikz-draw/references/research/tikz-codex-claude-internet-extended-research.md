# Deep Research: Making Codex and Claude Generate Better, More Structural TikZ

Date: 2026-04-19
Extends: [tikz-codex-claude-deep-research.md](/home/hoanganhduc/tikz-codex-claude-deep-research.md)

## Scope

This report extends the earlier official-doc-only report with selected high-trust internet sources:

- official OpenAI / Codex docs and cookbooks
- official Anthropic / Claude docs and engineering materials
- official PGF/TikZ manual pages and CTAN package manuals
- primary research papers

Excluded on purpose:

- forum posts
- Stack Exchange answers
- random blogs
- secondary summaries not anchored in primary sources

This is a targeted, high-trust expansion, not an exhaustive census of the whole internet.

## Coverage and limits

Inspected evidence classes:

- OpenAI API / Codex docs and cookbook pages on prompting, structured outputs, skills, and long-running workflows
- Anthropic docs on adaptive thinking, effort, skills, and validator-style workflows
- official PGF/TikZ and CTAN package documentation for structural diagram families
- primary papers on TikZ generation, constrained decoding, and structure-aware code generation

Important limit:

- in the sources inspected, I found direct TikZ evidence for compile / render / repair loops, but not a strong direct TikZ literature for grammar-constrained decoding during token generation

## Executive Summary

The earlier report argued that Codex and Claude should generate TikZ through a structural intermediate representation rather than free-form coordinate-heavy prompting. The internet-expanded pass strengthens that conclusion substantially.

What is new:

- Official OpenAI and Anthropic sources both support schema-first, validator-backed, workflow-based generation rather than one-shot “just be more careful” prompting. [O1][O2][O3][O4][C2][C4]
- Official TeX sources show that “better TikZ” often means choosing the correct structural package for the diagram family before writing raw TikZ. [T1][T2][T3][T4][T5][T6]
- Primary papers now provide direct TikZ evidence: recent work treats TikZ as a structured program target, uses compile-log feedback, render-aware rewards, and iterative refinement, and outperforms strong general-purpose baselines on TikZ generation tasks. [L1][L2][L3]
- The strongest negative nuance is also new: naive hard grammar constraints are not automatically a win, and for TeX/TikZ specifically one paper argues standard parse-tree constrained decoding is a poor fit because TeX syntax is unusually flat and hard to parse. [L1][L5]

Bottom line:

1. Use a structure-first pipeline.
2. Route by diagram family to the right TikZ package/library.
3. Use validation / compilation / render feedback loops.
4. Tune effort and skill metadata, not just the prompt body.

## Key Findings

### 1. Structure-first generation is now supported by direct TikZ literature

**Observation.** `AutomaTikZ` frames TikZ as an intermediate representation for scientific figures rather than plain text and reports that TikZ-trained models can outperform GPT-4 and Claude 2 on figure similarity and alignment tasks. [L1]

**Observation.** `DeTikZify` treats figure/sketch-to-TikZ as program synthesis and improves results with iterative search refinement rather than one-shot output. [L2]

**Observation.** `TikZilla` shows that better TikZ-focused data and render-aware reinforcement learning improve text-to-TikZ fidelity. [L3]

**Inference.** The earlier recommendation to use a typed structural spec before final TikZ is no longer just a product-doc analogy. It is now supported by direct TikZ-generation papers.

**Recommendation.** For nontrivial TikZ tasks, use a pipeline like:

1. classify the diagram family
2. emit a structured diagram spec / AST
3. render TikZ from that spec
4. compile / validate
5. repair from diagnostics

### 2. Validation loops are strongly supported; naive hard constraints are not

**Observation.** `AutomaTikZ` explicitly says constrained decoding methods based on parse trees and context-free grammars are unsuitable for its TikZ setup because TeX syntax is flat and generally hard to parse. It replaces that with compile-log-guided iterative resampling. [L1]

**Observation.** `DeTikZify` compiles generated TikZ with a LaTeX engine and uses compiler diagnostics and compiled-image similarity as reward signals inside its search loop. [L2]

**Observation.** `Synchromesh` shows constrained semantic decoding can materially improve reliability for structured languages such as `Vega-Lite`, SQL, and program DSLs by enforcing syntax, scoping, and typing constraints. [L4]

**Observation.** `Grammar-Aligned Decoding` shows that grammar-constrained decoding can distort model probabilities and hurt output quality if done naively. [L5]

**Inference.** The best-supported rule is not “always use hard constraints.” It is:

- use structural contracts and validators
- use compile / render feedback when available
- use hard decoding constraints carefully and only where the target language admits them cleanly

**Recommendation.** For TikZ specifically, prefer:

- schema or AST constraints before code generation
- compile-log validation after generation
- render-aware repair loops

Do not assume token-level grammar masking alone will solve TikZ quality.

### 3. Codex / OpenAI guidance now points to narrower, more deterministic skills

**Observation.** OpenAI’s coding guidance recommends explicit coding workflows for long-running agentic tasks: planning thoroughly, giving clear preambles for major tool choices, and tracking work with a TODO tool. [O1]

**Observation.** OpenAI’s GPT-5 prompting guidance adds a maintainability pattern: keep outward status verbosity low while explicitly asking for high readability in the generated code itself. [O2]

**Observation.** OpenAI’s function-calling guidance recommends making invalid states unrepresentable via explicit schemas, enums, and object structure. [O3]

**Observation.** Codex customization docs emphasize progressive disclosure for skills: discovery starts from `name` and `description`, `SKILL.md` is loaded only when needed, and clear descriptions improve triggering reliability. [O4]

**Observation.** OpenAI cookbook material from the scout pass strengthens this further with operational guidance for skill triggers, version pinning, schema-backed outputs, and `PLANS.md`-style restartable workflows. [O5][O6][O7][O8]

**Inference.** The Codex-side TikZ workflow should not be a giant general “diagram” skill. It should be a narrow, deterministic skill with:

- exact trigger language
- an explicit intermediate schema
- validation steps
- clear non-goals

**Recommendation.** For Codex, define one narrow skill such as `tikz-structural-diagrams` with:

- explicit trigger terms: `TikZ`, `LaTeX diagram`, `nodes`, `edges`, `coordinates`, `matrix`, `graph drawing`
- explicit non-triggers: general SVG art, freehand illustration, bitmap graphics
- a fixed workflow: `spec -> render -> compile/validate -> repair`
- deterministic helper scripts where available

### 4. Claude / Anthropic guidance supports adaptive thinking plus validator loops

**Observation.** Anthropic’s current recommendation for recent coding-capable models is `adaptive` thinking with explicit `effort`, not a generic “turn on extended thinking.” [C1][C2]

**Observation.** For Claude Opus 4.7, Anthropic recommends starting at `xhigh` for coding and agentic work and warns that `max` can overthink some structured tasks. [C2]

**Observation.** Anthropic documents that with thinking enabled, tool use is limited to `auto` or `none`, and thinking blocks must be preserved across tool turns. [C3]

**Observation.** Anthropic’s skill authoring guidance emphasizes metadata-driven discovery, concise `SKILL.md`, shallow reference structure, feedback loops, and matching the degree of freedom to task fragility. [C4]

**Observation.** Anthropic explicitly recommends validator-style workflows: “Run validator → fix errors → repeat.” [C4]

**Observation.** Anthropic’s Agent Skills docs and engineering post say progressive disclosure is the core design principle and deterministic code inside skills improves repeatability when reliability matters. [C5][C6]

**Inference.** Claude-side TikZ generation should be split into two regimes:

- low-freedom structural passes for schema, naming, package selection, and validation
- higher-freedom styling passes after structural correctness is settled

**Recommendation.** For Claude:

- use `adaptive` thinking where available
- use `medium` effort as the routine baseline for ordinary TikZ generation on Sonnet-class surfaces
- raise to `high` or `xhigh` only for dense, repair-heavy, or constraint-heavy diagrams
- use an `auto` compile/validate/repair loop instead of forcing tool use
- add explicit anti-overengineering guardrails such as:
  - work directly
  - avoid disposable helper scripts unless needed
  - do not add hard-coded coordinate patches when a structural library can express the layout

### 5. Official TeX sources support a package-family router

**Observation.** `forest` provides bracket-encoded tree input, a compact packing algorithm, and structural references for trees, making it preferable to generic hand-placed TikZ trees in many cases. [T1]

**Observation.** `tikz-cd` is explicitly designed to make commutative diagrams easier, with a matrix-backed model and diagram-specific arrow handling. [T2]

**Observation.** The PGF/TikZ `chains` manual explicitly says it often makes sense to use matrices for placement and chains for connections. [T3]

**Observation.** The `automata` and `mindmap` libraries are both official structural libraries: one for state-machine style diagrams, the other for mind maps and concept maps using tree mechanics. [T4][T5]

**Observation.** `pgf-umlsd` provides a sequence-diagram DSL where users describe diagram logic and the package generates the figure, though manual adjustment may still be needed in edge cases. [T6]

**Observation.** Narrower CTAN packages further support this family-routing pattern:

- `tikz-dependency` for dependency graphs [T8]
- `tikz-network` for complex networks [T9]
- `messagepassing` for communication protocols [T10]
- `smartdiagram` for diagrams generated from item lists [T7]

**Inference.** “More structural TikZ” should mean:

- identify the diagram family first
- use the family-native package or library if one exists
- use raw coordinates only as a fallback or local override

**Recommendation.** Use this router by default:

- Trees: `forest`
- Commutative diagrams: `tikz-cd`
- Finite automata / Turing-machine-like state diagrams: `automata` + `positioning`
- Mind maps / concept maps: `mindmap`
- Ordered pipelines / branching flows on a grid: `matrix` + `chains`
- UML sequence diagrams: `pgf-umlsd`
- Dependency graphs: `tikz-dependency`
- Complex networks: `tikz-network`
- Communication protocols: `messagepassing`
- Simple list-driven presentation diagrams: `smartdiagram`

## Recommended Workflow

### Shared workflow

The strongest internet-backed workflow is:

1. `classify`
   - Determine diagram family.
   - Choose the package/library before generating code.

2. `spec`
   - Produce a structural intermediate object.
   - Make invalid states hard to express.

3. `render`
   - Generate package-native TikZ or DSL code.

4. `validate`
   - Compile when possible.
   - Check compiler diagnostics.
   - Check render similarity or structural sanity where available.

5. `repair`
   - Fix from diagnostics.
   - Re-run validation.

### Suggested intermediate schema

This is a synthesized recommendation from the inspected sources, not a vendor-prescribed schema:

```json
{
  "diagram_family": "tree | commutative_diagram | automaton | mindmap | chain_flow | sequence_diagram | network | custom",
  "tikz_backend": "forest | tikz-cd | automata | mindmap | matrix+chains | pgf-umlsd | tikz-network | raw-tikz",
  "global_styles": {
    "node_style": "draw, align=center",
    "edge_style": "->"
  },
  "nodes": [],
  "edges": [],
  "groups": [],
  "layout_constraints": [],
  "validation_rules": [
    "prefer structural package-native constructs over absolute coordinates",
    "centralize repeated styles",
    "fail if package choice and diagram family disagree"
  ]
}
```

## Practical Settings

### Codex

Recommended baseline:

- durable guidance in `AGENTS.md` or a narrow skill
- `model_verbosity = "high"` when you want readable generated TikZ, but keep outward/status verbosity concise
- `model_reasoning_effort = "medium"` for ordinary structure-first TikZ work
- raise to `high` for difficult multi-cluster layouts or major refactors from coordinate-heavy legacy TikZ

Use a plan/spec artifact for nontrivial diagrams, especially if multiple passes or validations are required. [O1][O2][O7]

### Claude

Recommended baseline:

- `adaptive` thinking where available [C1]
- `medium` effort for ordinary TikZ generation on Sonnet-class surfaces [C2]
- `high` or `xhigh` only when the figure is dense, repair-heavy, or validation-heavy [C2]
- stable, minimal skill set; do not load unrelated skills [C5][C6]

## Source-Strength Summary

Strongest direct evidence:

- official OpenAI and Anthropic docs for skills, workflow structure, and effort controls [O1][O3][O4][C2][C4]
- official CTAN / PGF docs for family-specific structural diagram packages [T1][T2][T3][T4][T5][T6]
- direct TikZ generation papers from 2024-2026 [L1][L2][L3]

Strong adjacent evidence:

- constrained decoding for formal languages and visualization DSLs [L4]
- structure-aware pretraining and AST-based code modeling [L6]
- diagram generation via other structural DSLs such as Graphviz DOT [L7]

Main uncertainty:

- I did not find strong direct positive TikZ evidence for token-level grammar-constrained decoding during generation

## Sources

### OpenAI / Codex

- `O1` OpenAI prompt engineering, coding guidance.  
  https://developers.openai.com/api/docs/guides/prompt-engineering#coding

- `O2` OpenAI GPT-5 prompting guide, system prompt and parameter tuning.  
  https://developers.openai.com/cookbook/examples/gpt-5/gpt-5_prompting_guide#system-prompt-and-parameter-tuning

- `O3` OpenAI function-calling best practices.  
  https://developers.openai.com/api/docs/guides/function-calling#best-practices-for-defining-functions

- `O4` Codex customization and skills.  
  https://developers.openai.com/codex/concepts/customization#skills

- `O5` OpenAI cookbook, skills in API, operational best practices.  
  https://developers.openai.com/cookbook/examples/skills_in_api#operational-best-practices

- `O6` OpenAI cookbook, Codex structured outputs in code review workflow.  
  https://developers.openai.com/cookbook/examples/codex/build_code_review_with_codex_sdk#codex-structured-outputs

- `O7` OpenAI cookbook article on `PLANS.md` for long-running Codex tasks.  
  https://developers.openai.com/cookbook/articles/codex_exec_plans

- `O8` OpenAI cookbook, GitLab quality/security workflow with schema validation and guardrails.  
  https://developers.openai.com/cookbook/examples/codex/secure_quality_gitlab#wrapping-up

### Anthropic / Claude

- `C1` Anthropic adaptive thinking.  
  https://platform.claude.com/docs/en/build-with-claude/adaptive-thinking

- `C2` Anthropic effort guidance.  
  https://platform.claude.com/docs/en/build-with-claude/effort

- `C3` Anthropic extended thinking.  
  https://platform.claude.com/docs/en/build-with-claude/extended-thinking

- `C4` Anthropic skill authoring best practices.  
  https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

- `C5` Anthropic Agent Skills API guide.  
  https://platform.claude.com/docs/en/build-with-claude/skills-guide

- `C6` Anthropic engineering post on Agent Skills.  
  https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills

- `C7` Anthropic prompting best practices, chained complex prompts.  
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices#chain-complex-prompts

### TikZ / TeX ecosystem

- `T1` `forest` manual.  
  https://mirrors.ctan.org/graphics/pgf/contrib/forest/forest-doc.pdf

- `T2` `tikz-cd` manual.  
  https://mirrors.ctan.org/graphics/pgf/contrib/tikz-cd/tikz-cd-doc.pdf

- `T3` PGF/TikZ `chains` manual page.  
  https://tikz.dev/library-chains

- `T4` PGF/TikZ `automata` manual page.  
  https://tikz.dev/library-automata

- `T5` PGF/TikZ `mindmap` manual page.  
  https://tikz.dev/library-mindmaps

- `T6` `pgf-umlsd` manual.  
  https://tug.ctan.org/graphics/pgf/contrib/pgf-umlsd/pgf-umlsd-manual.pdf

- `T7` CTAN `smartdiagram` package page.  
  https://www.ctan.org/pkg/smartdiagram?lang=en

- `T8` CTAN `tikz-dependency` package page.  
  https://ctan.org/pkg/tikz-dependency?lang=en

- `T9` CTAN `tikz-network` package page.  
  https://ctan.org/pkg/tikz-network

- `T10` CTAN `messagepassing` package page.  
  https://ctan.org/pkg/messagepassing?lang=en

### Primary papers

- `L1` *AutomaTikZ: Text-Guided Synthesis of Scientific Vector Graphics with TikZ* (ICLR 2024 poster).  
  https://openreview.net/forum?id=v3K5TVP8kZ

- `L2` *DeTikZify: Synthesizing Graphics Programs for Scientific Figures and Sketches with TikZ* (NeurIPS 2024 spotlight).  
  https://openreview.net/forum?id=bcVLFQCOjc

- `L3` *TikZilla: Scaling Text-to-TikZ with High-Quality Data and Reinforcement Learning* (ICLR 2026 poster).  
  https://openreview.net/forum?id=rJv2byEWA3

- `L4` *Synchromesh: Reliable Code Generation from Pre-trained Language Models* (ICLR 2022 poster).  
  https://openreview.net/forum?id=KmtVD97J43e

- `L5` *Grammar-Aligned Decoding* (NeurIPS 2024).  
  https://openreview.net/forum?id=jWDWeLznqZ

- `L6` *AST-T5: Structure-Aware Pretraining for Code Generation and Understanding* (ICML 2024 poster).  
  https://openreview.net/forum?id=cBWVJh5Fvf

- `L7` *LegalViz: Legal Text Visualization by Text To Diagram Generation* (NAACL 2025).  
  https://aclanthology.org/2025.naacl-long.339/
