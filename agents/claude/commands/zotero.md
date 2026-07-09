Manage the user's Zotero library (10,000+ papers). Use the skill runner to execute commands.

**Runner:** `bash ~/.claude/skills/_run.sh skills/zotero/run_zot.sh <args>`
**Python direct:** `cd ~/.claude && PYTHONPATH="$HOME/.claude/.local:$PYTHONPATH" python3 skills/zotero/zot.py <args>`

User's request: $ARGUMENTS

## Routing

- "get / send / find / retrieve <paper>" → `run_zot.sh --json get "<query>"`
- "share link" → `run_zot.sh --json get --link "<query>"`
- "add <DOI/arXiv/URL>" → `run_zot.sh add "<identifier>" --collection "<name>"`
- "add file / add local PDF / add EPUB" → `run_zot.sh add-file "<path>" [--identifier "<DOI>"] --collection "<name>"`
- "search <query>" → `zot.py search "<query>" [--json|--bibtex]`
- "list collections" → `zot.py list-collections --tree [--json]`
- "update <key>" → `run_zot.sh update <key> --item-type|--attach-pdf|--attach-file "<path>"|--add-collection|--remove-collection`
- "trash <query>" → `zot.py --json trash "<query>"`
- "doctor" → `zot.py doctor`

## Mandatory rules

1. **arXiv/preprints** must have itemType `manuscript` (not `preprint`). After add, run: `run_zot.sh update <key> --item-type manuscript`
2. **PDF naming** follows ZotFile pattern `{%a_}{%y_}{%t} {[%T]}` — verify in output
3. **Collection assignment** — never add papers without a collection. List collections first, suggest matches, let user pick
4. **Deduplication** — different versions (arXiv vs journal) are intentionally kept separate. Only deduplicate by exact DOI match
5. **Multi-result disambiguation** — if multiple results, show numbered list, ask user to pick, then use `--index N`
6. **Pagination bug** — the `collections()` API only returns 100 at a time. If a collection is "not found", it may be beyond page 1
