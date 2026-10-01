# Public Export

`make backup-public` is the personal rebuild backup path. It is not the public
sharing path because it may preserve operational context that is useful to the
owner but inappropriate for publication.

Use `bin/public-export.sh` or `make public-export` to create a history-free
public export from a reviewed allowlist.

```bash
PUBLIC_EXPORT_OUT=/tmp/coding-system-public make public-export
```

The export excludes local state, planning notes, learning ledgers, staging
outputs, external component clones, secret inventories, observed runtime state,
agent provider state, caches, logs, and archives. Files with path names that
suggest authentication, credentials, secrets, or tokens are excluded unless
they are explicit public examples, templates, or schemas.

The initial allowlist is deliberately small. Add source, docs, tests, workflow
files, or skill directories only after they are sanitized and verified as public
safe.

Verification runs the normal leak scanner plus extra privacy checks for local
home paths, real-looking emails, UUIDs, long numeric identifiers, identifier
fields, private-key markers, token-shaped strings, and secret-shaped JSON
values.

Every allowed exception must be listed in `public-export-exceptions.yaml` with a
path, scanner class, exact line, reason, and proof that the value is fake or
public.
