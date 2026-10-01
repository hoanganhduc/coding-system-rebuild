# Coding System Rebuild — single entrypoint.
# Common env: RECOVERY_SET=/path/to/set CSR_ESCROW_SHARE_{1,2}_FILE=/protected/share SKIP_*=1 LOCAL=1
SHELL := /bin/bash
REPO  := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DENY  := $(HOME)/.config/coding-system/leak-denylist.txt

.PHONY: help doctor init-private sync backup secrets-pack verify-secrets restore-secrets restore-owner-data closure-drift \
        leak-scan leak-scan-history public-export verify-public-export public-export-check push install-git-hooks test verify smoke roundtrip status clean \
        prepare install components restore verify-schedulers scheduler-status recovery-drill refresh-lock ci

help: ## list targets
	@grep -hE '^[a-z][a-z-]*:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

doctor: ## preflight checks (OS, arch, disk, tools)
	@bash bin/doctor.sh

init-private: ## one-time source-machine setup (7zip, bashrc split, denylist, units.state)
	@/usr/bin/bash -p bin/init-private.sh

setup-tailscale: ## write tailscale authority, create signed recovery set, sync offsite
	@/usr/bin/bash -p bin/setup-tailscale-key.sh

rotate-keys: ## fail closed: in-place secret rotation is retired; use each canonical authority's native workflow
	@bash bin/rotate-keys.sh $(if $(SECRET),SECRET=$(SECRET)) $(if $(PROVIDER),PROVIDER=$(PROVIDER)) $(P)

list-secrets: ## explain the retired in-place rotation boundary (no values)
	@bash bin/rotate-keys.sh --list

verify-secret: ## live-test a deployed secret works. e.g. make verify-secret SECRET=ZOTERO_API_KEY
	@python3 bin/lib/verify_secret.py $(SECRET)$(PROVIDER)

ci-secrets: ## set GitHub Actions key secrets from live config (gh). ARGS=--dry-run to preview
	@bash bin/set-ci-secrets.sh $(ARGS)

sync: ## dry-run capture into .staging/ (fail-closed; no repo changes)
	@bash bin/sync.sh --dry-run

# ---- backup pre-gates: source-machine authorities must exist (hard fail) ----
define PUBLIC_BACKUP_GATES
	@test -f $(DENY) || { echo "GATE FAIL: denylist missing — run make init-private"; exit 2; }
	@grep -q '>>> coding-system secrets >>>' $(HOME)/.bashrc || { echo "GATE FAIL: bashrc markers missing — run make init-private"; exit 2; }
	@test -s system/systemd/units.state || { echo "GATE FAIL: units.state missing — run make init-private"; exit 2; }
endef

define RECOVERY_BACKUP_GATES
	@test -s $(HOME)/.config/coding-system/recovery-master.key || { echo "GATE FAIL: recovery master missing — run make init-private"; exit 2; }
	@test -s $(HOME)/.config/coding-system/escrow/current/escrow-generation.json || { echo "GATE FAIL: current escrow generation missing — run make init-private"; exit 2; }
	@test -s $(HOME)/.config/coding-system/recovery-signing || { echo "GATE FAIL: recovery signing authority missing — run make init-private"; exit 2; }
endef

backup-public: ## refresh state + sync --apply + leak-scan + local public commit
	$(PUBLIC_BACKUP_GATES)
	@bash bin/backup-transaction.sh public

backup: ## alias for safe public capture; publish HEAD before creating recovery media
	$(PUBLIC_BACKUP_GATES)
	@bash bin/backup-transaction.sh public

secrets-pack: ## create an immutable encrypted recovery-set generation
	@/usr/bin/bash -p bin/secrets-pack.sh

offsite: ## upload/readback-check the newest immutable recovery set (rclone)
	@bash bin/offsite-sync.sh

verify-secrets: ## verify live secrets or authenticate RECOVERY_SET with two share-file paths
	@/usr/bin/bash -p bin/secrets-verify.sh

restore-secrets: ## restore authenticated RECOVERY_SET into $$HOME (two share-file paths required)
	@/usr/bin/bash -p bin/secrets-restore.sh

restore-owner-data: ## restore OWNER_DATA=openclaw-private-*.tar.gz.gpg into OpenClaw
	@test -n "$(OWNER_DATA)" || { echo "OWNER_DATA is required" >&2; exit 2; }
	@/usr/bin/bash -p bin/restore-openclaw-owner-data.sh "$(OWNER_DATA)"

closure-drift: ## report installed/upstream drift without changing release locks
	@python3 bin/check-closure-drift.py --upstream

leak-scan: ## scan the repo working tree for secrets/personal IDs
	@bash bin/leak-scan.sh

leak-scan-history: ## scan every commit's full tree (mandatory before first push)
	@rc=0; for sha in $$(git rev-list --all); do \
	  t=$$(mktemp -d); git archive $$sha | tar -x -C $$t; \
	  bash bin/leak-scan.sh $$t >/dev/null 2>&1 || { echo "findings in commit $$sha:"; bash bin/leak-scan.sh $$t | head -20; rc=2; }; \
	  rm -rf $$t; done; \
	  [ $$rc -eq 0 ] && echo "history scan: clean ($$(git rev-list --all --count) commits)"; exit $$rc

public-export: ## create a history-free public export at PUBLIC_EXPORT_OUT
	@test -n "$(PUBLIC_EXPORT_OUT)" || { echo "PUBLIC_EXPORT_OUT is required" >&2; exit 2; }
	@bash bin/public-export.sh --output "$(PUBLIC_EXPORT_OUT)" $(if $(REF),--ref "$(REF)",)

verify-public-export: ## verify an existing public export at PUBLIC_EXPORT_OUT
	@test -n "$(PUBLIC_EXPORT_OUT)" || { echo "PUBLIC_EXPORT_OUT is required" >&2; exit 2; }
	@python3 -I -B bin/lib/public_export.py verify --repo "$(REPO)" --target "$(PUBLIC_EXPORT_OUT)"

public-export-check: ## create and verify a temporary public export from committed HEAD
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	  ref="$${REF:-$$(git rev-parse HEAD)}"; \
	  bash bin/public-export.sh --output "$$tmp/export" --ref "$$ref"; \
	  python3 -I -B bin/lib/public_export.py verify --repo "$(REPO)" --target "$$tmp/export"

push: ## leak-scan, require the installed pre-push gate, then git push (manual publish step)
	@bash bin/leak-scan.sh
	@hooks="$$(git config --get core.hooksPath)"; \
	  [ -n "$$hooks" ] && cmp -s "$$hooks/pre-push" system/git-hooks/pre-push \
	  || { echo "FAIL: the current pre-push gate is not installed; run make install-git-hooks" >&2; exit 2; }
	@git push

install-git-hooks: ## install the private pre-push gate and enable it here (REPOS="dir ..." for more repositories)
	@install -d -m 0700 "$$HOME/.config/coding-system/git-hooks"
	@install -m 0700 system/git-hooks/pre-push "$$HOME/.config/coding-system/git-hooks/pre-push"
	@for repo in . $(REPOS); do \
	  git -C "$$repo" config core.hooksPath "$$HOME/.config/coding-system/git-hooks" && echo "pre-push gate enabled: $$repo"; \
	done

test: ## self-tests: canary scan + field-set guard + rotation units + grok-proxy + roundtrip
	@bash tests/leak_scan_selftest.sh
	@python3 -B tests/test_prepush_hook.py
	@python3 -B tests/test_manifest_sync_privacy.py
	@bash tests/field_set_sync.sh
	@bash tests/rotation_unit.sh
	@python3 -B tests/test_public_export.py
	@python3 -B tests/test_aas_component.py
	@python3 -B tests/test_component_paths.py
	@python3 -B tests/test_closure_drift.py
	@python3 -B tests/test_lock_promotion.py
	@python3 -B tests/test_npm_closure_relock.py
	@python3 -B tests/test_host_services.py
	@python3 -B tests/test_host_diff.py
	@python3 -I -B tests/test_init_private.py
	@python3 -B tests/test_migrate_codex_config.py
	@python3 -B tests/test_render_install.py
	@python3 -B tests/test_install_closure.py
	@python3 -B tests/test_materialize_openclaw_runtime.py
	@python3 -B tests/test_secret_projections.py
	@python3 -B tests/test_skill_credentials.py
	@python3 -B tests/test_vnu_eoffice_restore.py
	@python3 -B tests/test_openclaw_compatibility.py
	@python3 -B tests/test_vendor_skills.py
	@python3 -B tests/test_bootstrap_software.py
	@python3 -B tests/test_python_closure.py
	@python3 -B tests/test_python_wheelhouse.py
	@python3 -B tests/test_lean_explore_wrapper.py
	@python3 -B tests/test_lean_explore_handshake.py
	@python3 -B tests/test_research_digest_wrapper.py
	@python3 -B tests/test_copilot_wrapper.py
	@python3 -B tests/test_mcp_config_verifier.py
	@python3 -B tests/test_installed_software_verifier.py
	@python3 -B tests/test_classroom50_restore.py
	@python3 -I -B tests/test_grok_bootstrap_provision.py
	@python3 -B tests/test_openclaw_cron_v2.py
	@python3 -B tests/test_recovery_hardening.py
	@python3 -B tests/test_recovery_tool.py
	@python3 -B tests/test_restore_transaction.py
	@python3 -B tests/test_escrow_distribution.py
	@python3 -B tests/test_restore_entrypoint.py
	@python3 -B tests/test_restore_report.py
	@python3 -B tests/test_scheduler_completion.py
	@python3 -B tests/test_share_resolution.py
	@python3 -B tests/test_target_state_verifier.py
	@python3 -B tests/test_owner_settings.py
	@python3 -B tests/test_repository_generation.py
	@python3 -B tests/test_openclaw_executable_contract.py
	@python3 -B tests/test_secret_restore_lifecycle.py
	@python3 -B tests/test_tailscale_authority.py
	@python3 -B tests/test_offsite_sync.py
	@python3 -B tests/test_workflow_security.py
	@python3 -B tests/test_opencode_wrapper.py
	@python3 -B tests/test_openclaw_skill_inventory.py
	@python3 -B tests/test_test_registration.py
	@component=$$(python3 -I -B bin/lib/component_paths.py --repository "$(REPO)" --home "$(HOME)" --source-fallback --require openclaw-bot); \
	  python3 -B "$$component/tests/test_runtime_contracts.py"
	@python3 tests/test_stage_backup.py
	@bash system/grok-proxy/tests/run.sh
	@bash bin/test-roundtrip.sh

ci: ## no-secrets rehearsal for CI/fresh VM: doctor + components + leak scans + all self-tests
	@bash bin/doctor.sh
	@python3 -I -B bin/lib/component_paths.py --repository "$(REPO)" --home "$(HOME)" --source-fallback --require openclaw-bot >/dev/null 2>&1 || $(MAKE) -s components
	@bash bin/leak-scan.sh
	@$(MAKE) -s leak-scan-history
	@$(MAKE) -s public-export-check
	@$(MAKE) -s test
	@echo "ci: all no-secrets checks passed"

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

components: ## materialize immutable components outside the repository plus AAS/VNU compatibility checkouts
	@bash bin/components.sh

install: ## full restore after bootstrap (RECOVERY_SET optional; degraded without)
	@/usr/bin/bash -p bin/install.sh

restore: ## internal sealed Stage-0 continuation; operators rerun trusted restore-ubuntu.sh
	@/usr/bin/bash -p bin/restore.sh

verify-schedulers: ## exact read-only host/systemd/OpenClaw scheduler verification
	@bash bin/verify-schedulers.sh --profile full

scheduler-status: ## read-only scheduler drift and canary status
	@bash bin/verify-schedulers.sh --profile status

recovery-drill: ## synthetic 2-of-4 encrypted recovery and hostile-archive regression drill
	@python3 -B tests/test_recovery_tool.py
	@python3 -B tests/test_restore_transaction.py

refresh-lock: ## report upstream drift; promotion remains a reviewed release operation
	@python3 system/software/lockctl.py validate
	@python3 bin/check-closure-drift.py --upstream

clean: ## remove staging and temp artifacts
	@rm -rf .staging
	@echo "cleaned .staging/"
