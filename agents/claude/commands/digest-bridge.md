Extract paper identifiers from research/RSS digests and create getscipapers manifests.

**Runner:** `cd ~/.claude && PYTHONPATH="$HOME/.claude/.local:$PYTHONPATH" python3 skills/digest-bridge/digest_bridge.py <args>`

User's request: $ARGUMENTS

## Commands

- Scan (dry run): `scan [--source research|rss|all] [--min-score N]`
- Create manifest & request: `request [--watch] [--min-score N] [--source research|rss|all]`
