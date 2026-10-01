# DeepSeek Local Tools

This directory is not auto-loaded by DeepSeek TUI. Scripts here are reference helpers for skills, MCP wrappers, or explicitly approved shell commands.

Use the DeepSeek skill wrappers under `~/.deepseek/skills` as the normal entry point.

The `codex-run-skill` helper delegates to:

```bash
bash ~/.codex/runtime/run_skill.sh
```

It does not copy Codex runtime files or secrets into `~/.deepseek`.
