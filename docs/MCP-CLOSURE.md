# MCP runtime closure

`system/software/mcp-policy.json` is the restore authority for MCP state. It
distinguishes three states instead of treating absence as success:

- **enabled/configured** — the restored server must start from a locked local
  runtime and complete `initialize` followed by `tools/list`;
- **intentionally disabled** — the declaration remains visible but restore does
  not contact it;
- **intentionally omitted** — no reviewed artifact closure exists, and the
  policy records why the server is absent.

A server whose launcher fetches code at run time (`npx`, `uvx`, a shell) is
refused unless the policy lists it under `floatingAllowed` with the owner's
reason; the report marks every such server.

The enabled set is deliberately small:

| Target | Enabled local servers | Locked runtime |
|---|---|---|
| Claude | `docling` | `python-closure/docling-cpu` (`docling-mcp==1.3.4`, `docling-mcp-server` entry point) |
| Codex | `lean-explore`, `openaiDeveloperDocs` | the checked-in launcher plus `python-closure/lean-explore`; the remote docs server over HTTPS |
| DeepSeek/CodeWhale | `lean-explore` | the LeanExplore closure |

LeanExplore API mode also needs `LEANEXPLORE_API_KEY`. The recovery set keeps
the key in the target-neutral AAS `skill.env`; a bounded migration removes any
historical copy from `~/.secrets.env`. The installed MCP launcher reads only its
protected declared source. LeanExplore 1.2.1's server CLI cannot safely carry
the API key without a command-line argument, so the launcher is an exact-version
compatibility adapter: it removes credential and pointer variables before any
LeanExplore import, constructs `ApiClient` in-process, and starts the registered
FastMCP app over stdio without creating a child process. The key is never put in
the launcher/server arguments or retained in the process environment.
Missing key material is a credential closure problem, not a reason to replace
the locked launcher with `uvx`.

By owner decision (2026-10-01) the restore keeps the servers the live host
runs: Codex's remote OpenAI developer-docs server is enabled, and Claude's
sequential-thinking, GitHub and Scrapling entries and Codex's sequential-thinking
entry are floating exceptions, so these four fetch their latest package when
they start and are not reproducible. The missing legacy `deepseek-tui` path is
not restored. CodeWhale's optional self-server is also omitted because its
initialize result is not a standard MCP initialize result; treating that
process start as a working MCP would be a false positive. The locked CodeWhale
CLI remains the supported DeepSeek-compatible agent surface.

`bin/verify-configured-mcps.py --mode declared` is the offline policy/config
gate used in CI. Full restore uses `--mode full` against the installed configs.
An enabled HTTP server fails the full offline-closure gate; it must either gain
a separately reviewed transport verifier or remain disabled.

The verifier never emits MCP arguments, environment values, stderr, tool names,
tool descriptions, or server-provided identity strings. Its mode-0600 JSON
report contains only configuration state, protocol compatibility, byte counts,
and tool counts. Consequently, even a hostile or broken server that writes a
credential to stderr cannot expose that credential through restore logs.

Target-state verification has two phases. Phase 8 uses
`--readiness-phase pre-runtime` and explicitly records MCP/scheduler evidence as
deferred. Final verification uses `--readiness-phase full`, consumes the MCP
report, and accepts scheduler readiness only when the scheduler verifier's
provider-free canaries passed.

## Diagnosing an initialize broken pipe

An MCP client message such as “failed to start”, “broken pipe”, or “startup
incomplete” is not accepted as a working integration merely because the
process existed briefly. After the Python closure and credentials have been
restored, run the same bounded, redacted handshake used by full verification:

```bash
python3 "$HOME/coding-system-rebuild/bin/verify-configured-mcps.py" \
  --repository "$HOME/coding-system-rebuild" \
  --root "$HOME" \
  --mode full \
  --output "$HOME/.local/state/coding-system/restore/mcp-verification.json"
```

For `lean-explore`, verify the rendered Codex/DeepSeek config points to the
checked-in launcher, the `lean-explore` Python environment is qualified and
installed, and the protected API-key authority exists. For `docling`, verify
the Claude config and `docling-cpu` environment. Do not diagnose by running a
similarly named script from the Zotero directory: the policy-selected target,
launcher, interpreter, and `initialize`/`tools/list` exchange are the evidence
that matters. The report deliberately omits server stderr and credential data;
use its state/reason codes and the full restore gate rather than copying raw
secret-bearing process output.
