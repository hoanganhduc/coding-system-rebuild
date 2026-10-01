# Verification Patterns

Core principle: **Existence ≠ Implementation**. A file existing does not mean it works.

## 4-Level Verification

1. **Exists** — File present at expected path
2. **Substantive** — Content is real implementation, not placeholder
3. **Wired** — Connected to rest of system (called, imported, configured)
4. **Functional** — Actually works when invoked

## Universal Stub Indicators

- Comment-based: `TODO`, `FIXME`, `XXX`, `HACK`, `PLACEHOLDER`, `NOT IMPLEMENTED`
- Placeholder text: `"Lorem ipsum"`, `"Example"`, `"test"` in output
- Empty/trivial: function body is `pass`, `return None`, `return {}`, `raise NotImplementedError`
- Hardcoded where dynamic expected: `return True`, `return []`, fixed strings

## Type-Specific Verification

### Python Scripts/Skills
- Export function exists with real body (>5 lines)
- Dependencies importable (`import X` doesn't raise)
- CLI entry point runs: `python script.py --help` exits 0
- Config file referenced exists and is valid JSON/YAML
- Output matches expected schema

### Shell Scripts
- Has shebang and `set -euo pipefail`
- Referenced commands exist (`command -v X`)
- File paths use variables, not hardcoded
- Exit codes are meaningful (0 success, non-zero failure)
- Runs without error: `bash -n script.sh` (syntax check)

### LaTeX Documents
- Compiles without errors: `latexmk -pdf doc.tex`
- References resolve: no `??` in output
- Bibliography entries cited: `\cite{key}` has matching `@article{key,...}`
- Figures referenced exist at path
- No orphan labels (defined but not referenced)

### SageMath Code
- Loads without error in sage interpreter
- Graph objects have expected properties (order, size, connectivity)
- Polynomial computations terminate (watch for exponential blowup)
- Results match known values for small cases

### Hook Scripts
- Registered in settings.json under correct event
- Stdin parsing handles empty/malformed input (exit 0, not crash)
- Timeout is set and reasonable
- Advisory hooks exit 0 always; blocking hooks exit 2 to deny

### Slash Commands
- Command file exists in `~/.claude/commands/`
- Referenced skill directory exists with runner script
- Runner script is executable and paths resolve
- No duplicate registration (SKILL.md frontmatter has `user-invocable: false`)

## Wiring Verification

- Script → Config: config file path exists and is readable
- Hook → Settings: hook command string in settings.json matches actual file path
- Skill → Runner: `_run.sh` sets correct env vars before invoking skill script
- Command → Skill: slash command's runner path matches skill's run script

## Quick Check Commands

```bash
# Syntax-check all shell hooks
for f in ~/.claude/hooks/*.sh ~/.claude/hooks/**/*.sh; do bash -n "$f" && echo "OK: $f"; done

# Verify all commands reference existing skills
for f in ~/.claude/commands/*.md; do grep -oP 'skills/\S+' "$f" | while read s; do [ -e ~/.claude/"$s" ] && echo "OK: $s" || echo "MISSING: $s"; done; done

# Check settings.json hook paths exist
grep -oP 'node [^ "]+|bash [^ "]+' ~/.claude/settings.json | while read cmd; do p="${cmd#* }"; eval p="$p"; [ -e "$p" ] && echo "OK: $p" || echo "MISSING: $p"; done
```
