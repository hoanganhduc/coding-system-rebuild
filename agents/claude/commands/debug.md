---
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, Agent
---

# Scientific Debugging with Persistent State

Use this command for non-trivial debugging that may span multiple context windows.

## Protocol

State persists in `~/.claude/data/debug/<issue-slug>/`:
- `hypotheses.md` — Active hypotheses with status (untested/confirmed/ruled-out)
- `evidence.md` — Evidence log with timestamps
- `timeline.md` — Chronological record of actions taken
- `resolution.md` — Final resolution (written on `/debug resolve`)

## Subcommands

### `/debug start <description>`
1. Create slug from description (lowercase, hyphens, max 40 chars)
2. Create state directory at `~/.claude/data/debug/<slug>/`
3. Initialize `hypotheses.md` with initial hypothesis list
4. Initialize `evidence.md` and `timeline.md` with headers
5. Output: "Debug session started: <slug>"

### `/debug status`
1. Find most recent debug session (by modification time)
2. Read and display: current hypotheses, latest evidence, next steps
3. If no active session: "No active debug session. Use /debug start <description>"

### `/debug hypothesis <text>`
1. Append new hypothesis to `hypotheses.md` with status `untested`
2. Add timeline entry

### `/debug test <hypothesis-number>`
1. Mark hypothesis as `testing` in `hypotheses.md`
2. Run the investigation
3. Update hypothesis status to `confirmed` or `ruled-out` with evidence
4. Add evidence entry and timeline entry

### `/debug resolve <summary>`
1. Write `resolution.md` with: summary, root cause, fix applied, lessons learned
2. Mark all remaining hypotheses as `closed`
3. Add timeline entry: "RESOLVED"
4. Suggest logging to `~/.claude/learnings/LEARNINGS.md` if non-obvious

## State File Formats

### hypotheses.md
```markdown
# Hypotheses — <issue description>

| # | Hypothesis | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Description | untested/testing/confirmed/ruled-out | Brief evidence |
```

### evidence.md
```markdown
# Evidence Log

## E1 — <timestamp>
**Source**: command output / file content / observation
**Finding**: what was found
**Supports**: H1, H3
**Contradicts**: H2
```

### timeline.md
```markdown
# Debug Timeline — <issue>

- <timestamp> — Session started
- <timestamp> — H1 added: description
- <timestamp> — Tested H1: ruled out (evidence E1)
- <timestamp> — RESOLVED: root cause was X
```

## Rules
- Always read existing state files before modifying
- Never delete state — append only (ruled-out hypotheses stay visible)
- Each evidence entry links to hypotheses it supports/contradicts
- On resolve, always consider if the finding is worth logging to learnings
