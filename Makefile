# Coding System Rebuild — single entrypoint.
# Common env: SECRETS=/path/to/secrets.zip  CSR_SECRETS_PASSWORD=...  SKIP_*=1  LOCAL=1
SHELL := /bin/bash
REPO  := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DENY  := $(HOME)/.config/coding-system/leak-denylist.txt

.PHONY: help doctor init-private sync backup secrets-pack verify-secrets restore-secrets \
        leak-scan leak-scan-history push test verify smoke roundtrip status clean \
        prepare install components

help: ## list targets
	@grep -hE '^[a-z][a-z-]*:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

doctor: ## preflight checks (OS, arch, disk, tools)
	@bash bin/doctor.sh

init-private: ## one-time source-machine setup (7zip, bashrc split, denylist, units.state)
	@bash bin/init-private.sh

sync: ## dry-run capture into .staging/ (fail-closed; no repo changes)
	@bash bin/sync.sh --dry-run

# ---- backup pre-gates: the four init-private mutations must exist (hard fail) ----
define BACKUP_GATES
	@command -v 7zz >/dev/null || command -v 7z >/dev/null || { echo "GATE FAIL: no 7zz/7z — run make init-private"; exit 2; }
	@test -f $(DENY) || { echo "GATE FAIL: denylist missing — run make init-private"; exit 2; }
	@grep -q '>>> coding-system secrets >>>' $(HOME)/.bashrc || { echo "GATE FAIL: bashrc markers missing — run make init-private"; exit 2; }
	@test -s system/systemd/units.state || { echo "GATE FAIL: units.state missing — run make init-private"; exit 2; }
endef

backup: ## refresh state + sync --apply + leak-scan + local commit + secrets zip
	$(BACKUP_GATES)
	@bash bin/refresh-state.sh
	@bash bin/sync.sh --apply
	@bash bin/leak-scan.sh
	@git add -A && { git diff --cached --quiet && echo "backup: no changes to commit" || \
	  { git commit -q -m "backup: $$(date -u +%F) — $$(git diff --cached --numstat | wc -l) files" && \
	    echo "committed:" && git show --stat --oneline -s HEAD; }; }
	@bash bin/secrets-pack.sh
	@echo "backup complete — review with 'git show', publish with 'make push'"

secrets-pack: ## regenerate the AES-256 secrets zip only
	@bash bin/secrets-pack.sh

verify-secrets: ## verify secrets vs manifest (live $$HOME, or SECRETS=zip)
	@bash bin/secrets-verify.sh $(SECRETS)

restore-secrets: ## extract SECRETS=zip into $$HOME + perm fixups
	@bash bin/secrets-restore.sh

leak-scan: ## scan the repo working tree for secrets/personal IDs
	@bash bin/leak-scan.sh

leak-scan-history: ## scan every commit's full tree (mandatory before first push)
	@rc=0; for sha in $$(git rev-list --all); do \
	  t=$$(mktemp -d); git archive $$sha | tar -x -C $$t; \
	  bash bin/leak-scan.sh $$t >/dev/null 2>&1 || { echo "findings in commit $$sha:"; bash bin/leak-scan.sh $$t | head -20; rc=2; }; \
	  rm -rf $$t; done; \
	  [ $$rc -eq 0 ] && echo "history scan: clean ($$(git rev-list --all --count) commits)"; exit $$rc

push: ## leak-scan, then git push (manual publish step)
	@bash bin/leak-scan.sh
	@git push

test: ## self-tests: canary scan + roundtrip
	@bash tests/leak_scan_selftest.sh
	@bash bin/test-roundtrip.sh

roundtrip: ## /tmp-prefix capture/render/secrets cycle (no live mutation)
	@bash bin/test-roundtrip.sh

verify: ## post-install health checks
	@bash bin/verify.sh

smoke: ## quick agent-CLI version smokes
	@bash bin/verify.sh --smoke

status: ## drift summary (sync dry-run + component pins)
	@bash bin/sync.sh --dry-run || true
	@bash bin/refresh-state.sh >/dev/null 2>&1 || true
	@git status --short | head -20

prepare: ## install all software (SKIP_* toggles; see docs/INSTALL.md)
	@bash bin/prepare.sh

components: ## clone/refresh pinned components into external/
	@bash bin/components.sh

install: ## full restore on a fresh machine (SECRETS=... optional, degraded without)
	@bash bin/install.sh

clean: ## remove staging and temp artifacts
	@rm -rf .staging
	@echo "cleaned .staging/"
