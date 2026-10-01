# Engineering Lifecycle

Use this flow for non-trivial engineering work.

## Lifecycle

1. **Spec**
2. **Plan**
3. **Tasks**
4. **Implement**
5. **Verify**

Do not skip directly to implementation when:

- requirements are ambiguous
- the work touches multiple files
- the work is architectural
- the task will likely take more than one focused session

## Required artifacts

Start from these templates:

- `~/.claude/templates/SPEC.md`
- `~/.claude/templates/tasks-plan.md`
- `~/.claude/templates/tasks-todo.md`

## Minimum workflow

### 1. Spec

- state objective
- state assumptions
- list commands (build, test, lint, run)
- define project-structure touchpoints
- define testing strategy
- define success criteria

### 2. Plan

- break the spec into implementation phases
- identify dependencies
- identify risks
- identify verification checkpoints

### 3. Tasks

- make tasks small and verifiable
- include acceptance criteria
- include verification steps
- include target files where practical

### 4. Implement

- work in small slices
- keep changes scoped
- prefer the simplest correct version first

### 5. Verify

- run the narrowest meaningful checks first
- run the most relevant regression checks before completion
- report exactly what was and was not verified

## Anti-rationalization reminders

| Rationalization | Response |
|---|---|
| "This is too small for a spec" | Use a smaller spec, not no spec. |
| "I will verify later" | Verification is a gate, not cleanup. |
| "While I am here, I should refactor nearby code" | Keep scope disciplined unless the task requires it. |
| "The user probably meant X" | State the assumption explicitly or ask briefly. |

## Suggested local commands

```bash
cp ~/.claude/templates/SPEC.md ./SPEC.md
```

```bash
mkdir -p tasks && \
cp ~/.claude/templates/tasks-plan.md ./tasks/plan.md && \
cp ~/.claude/templates/tasks-todo.md ./tasks/todo.md
```

## Completion checklist

- [ ] A spec exists for non-trivial work
- [ ] A plan exists
- [ ] Tasks are explicit
- [ ] Implementation stayed scoped
- [ ] Verification results are reported concretely

## Relationship to TaskCreate

`TaskCreate` tracks in-session progress. It is **not a substitute for** a Spec or Plan file — those persist across sessions and give reviewers something to read. Use TaskCreate to implement the task list; use the templates to record what the task list is for.
