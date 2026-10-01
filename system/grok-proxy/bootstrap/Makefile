_CALLER_CC_ORIGIN := $(origin CC)
_CALLER_PKG_CONFIG_ORIGIN := $(origin PKG_CONFIG)
_CALLER_BUILD_DIR_ORIGIN := $(origin BUILD_DIR)
_CALLER_CPPFLAGS_ORIGIN := $(origin CPPFLAGS)
_CALLER_CFLAGS_ORIGIN := $(origin CFLAGS)
_CALLER_LDFLAGS_ORIGIN := $(origin LDFLAGS)
_CALLER_TEST_MODE_ORIGIN := $(origin TEST_MODE)
_CALLER_TEST_DESTDIR_ORIGIN := $(origin TEST_DESTDIR)
_CALLER_TEST_FAIL_AT_ORIGIN := $(origin TEST_FAIL_AT)

override SHELL := /bin/sh
override PATH := /usr/bin:/bin
override LANG := C
override LC_ALL := C
export PATH LANG LC_ALL
override CC := /usr/bin/cc
override PKG_CONFIG := /usr/bin/pkg-config
override BUILD_DIR := build
NATIVE_TARGET := $(BUILD_DIR)/grok-bootstrap
PUBLISHER_TARGET := $(BUILD_DIR)/grok-bootstrap-publisher.py
PUBLISHER_LAUNCHER_TARGET := $(BUILD_DIR)/grok-bootstrap-publisher
ACTIVATOR_TARGET := $(BUILD_DIR)/activate_package.py
ACTIVATOR_LAUNCHER_TARGET := $(BUILD_DIR)/grok-bootstrap-package-activate
TARGETS := $(NATIVE_TARGET) $(PUBLISHER_TARGET) $(PUBLISHER_LAUNCHER_TARGET) \
	$(ACTIVATOR_TARGET) $(ACTIVATOR_LAUNCHER_TARGET)

override CPPFLAGS := -D_FORTIFY_SOURCE=3
override CFLAGS := -std=c11 -O2 -g0 -fPIE -fstack-protector-strong \
	-Wall -Wextra -Werror -Wconversion -Wformat=2 -Wshadow \
	-Wstrict-prototypes -Wundef
override LDFLAGS := -Wl,-z,relro,-z,now -pie
override LAUNCHER_CFLAGS := -std=c11 -Os -g0 -ffreestanding -fno-builtin \
	-fno-stack-protector -fno-pie -fno-asynchronous-unwind-tables \
	-fno-unwind-tables -Wall -Wextra -Werror -Wconversion \
	-Wformat=2 -Wshadow -Wundef
override LAUNCHER_LDFLAGS := -nostdlib -static -no-pie -Wl,-e,_start \
	-Wl,--build-id=none -Wl,-z,noexecstack -Wl,--fatal-warnings -Wl,-s

.NOTPARALLEL:
.PHONY: all check-nonroot check-build-controls check-key install install-test FORCE

all: check-nonroot check-build-controls $(TARGETS)

check-nonroot:
	@test "$$('/usr/bin/id' -u)" != 0 \
		|| { echo "Grok package Make targets must never run as root" >&2; exit 2; }

check-build-controls: check-nonroot
	@set -eu; \
		for pair in \
			'CC:$(_CALLER_CC_ORIGIN)' \
			'PKG_CONFIG:$(_CALLER_PKG_CONFIG_ORIGIN)' \
			'BUILD_DIR:$(_CALLER_BUILD_DIR_ORIGIN)' \
			'CPPFLAGS:$(_CALLER_CPPFLAGS_ORIGIN)' \
			'CFLAGS:$(_CALLER_CFLAGS_ORIGIN)' \
			'LDFLAGS:$(_CALLER_LDFLAGS_ORIGIN)'; do \
			name="$${pair%%:*}"; origin="$${pair#*:}"; \
			test "$$origin" != 'command line' \
				|| { echo "$$name is controlled by this Makefile" >&2; exit 2; }; \
		done

check-key: check-build-controls
	@test -n "$(KEY_ID)" || { echo "KEY_ID is required" >&2; exit 2; }
	@printf '%s' "$(KEY_ID)" | /usr/bin/grep -Eq '^[A-Za-z0-9._-]{1,64}$$' \
		|| { echo "KEY_ID is invalid" >&2; exit 2; }
	@printf '%s' "$(PUBLIC_KEY_HEX)" | /usr/bin/grep -Eq '^[0-9a-f]{64}$$' \
		|| { echo "PUBLIC_KEY_HEX must be 64 lowercase hex characters" >&2; exit 2; }

$(NATIVE_TARGET): bootstrap.c FORCE check-key
	@/usr/bin/mkdir -p "$(BUILD_DIR)"
	@/usr/bin/chmod 0755 "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) \
		-DGROK_BOOTSTRAP_TEST_BUILD=0 \
		-DGROK_BOOTSTRAP_KEY_ID='"$(KEY_ID)"' \
		-DGROK_BOOTSTRAP_PUBLIC_KEY_HEX='"$(PUBLIC_KEY_HEX)"' \
		$$($(PKG_CONFIG) --cflags openssl) bootstrap.c -o "$@" \
		$(LDFLAGS) $$($(PKG_CONFIG) --libs openssl)
	@/usr/bin/chmod 0555 "$@"

$(PUBLISHER_TARGET): publish_signed_application.py FORCE check-build-controls
	@/usr/bin/mkdir -p "$(BUILD_DIR)"
	@/usr/bin/chmod 0755 "$(BUILD_DIR)"
	/usr/bin/install -m 0444 publish_signed_application.py "$@"

$(PUBLISHER_LAUNCHER_TARGET): isolated_python_launcher.c FORCE check-build-controls
	@/usr/bin/mkdir -p "$(BUILD_DIR)"
	@/usr/bin/chmod 0755 "$(BUILD_DIR)"
	$(CC) $(LAUNCHER_CFLAGS) \
		-DGROK_LAUNCHER_SCRIPT='"/usr/local/libexec/grok-proxy/bootstrap/grok-bootstrap-publisher.py"' \
		-DGROK_LAUNCHER_FORWARD_ARGS=1 isolated_python_launcher.c \
		$(LAUNCHER_LDFLAGS) -o "$@"
	@/usr/bin/chmod 0555 "$@"
	@! /usr/bin/readelf -lW "$@" | /usr/bin/grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$$)'
	@! /usr/bin/readelf -dW "$@" | /usr/bin/grep -Eq '\(NEEDED\)'
	@test -z "$$('/usr/bin/nm' -u -- "$@" 2>/dev/null)"
	@set -eu; case "$$($(CC) -dumpmachine)" in \
		x86_64*) expected='Advanced Micro Devices X86-64' ;; \
		aarch64*) expected='AArch64' ;; \
		*) echo 'unsupported static-launcher target architecture' >&2; exit 2 ;; \
		esac; /usr/bin/readelf -hW "$@" \
		| /usr/bin/grep -Eq "Machine:[[:space:]]+$$expected$$"

$(ACTIVATOR_TARGET): activate_package.py FORCE check-build-controls
	@/usr/bin/mkdir -p "$(BUILD_DIR)"
	@/usr/bin/chmod 0755 "$(BUILD_DIR)"
	/usr/bin/install -m 0444 activate_package.py "$@"

$(ACTIVATOR_LAUNCHER_TARGET): isolated_python_launcher.c FORCE check-build-controls
	@/usr/bin/mkdir -p "$(BUILD_DIR)"
	@/usr/bin/chmod 0755 "$(BUILD_DIR)"
	$(CC) $(LAUNCHER_CFLAGS) \
		-DGROK_LAUNCHER_SCRIPT='"/usr/libexec/grok-bootstrap-package/activate_package.py"' \
		-DGROK_LAUNCHER_FORWARD_ARGS=0 isolated_python_launcher.c \
		$(LAUNCHER_LDFLAGS) -o "$@"
	@/usr/bin/chmod 0555 "$@"
	@! /usr/bin/readelf -lW "$@" | /usr/bin/grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$$)'
	@! /usr/bin/readelf -dW "$@" | /usr/bin/grep -Eq '\(NEEDED\)'
	@test -z "$$('/usr/bin/nm' -u -- "$@" 2>/dev/null)"
	@set -eu; case "$$($(CC) -dumpmachine)" in \
		x86_64*) expected='Advanced Micro Devices X86-64' ;; \
		aarch64*) expected='AArch64' ;; \
		*) echo 'unsupported static-launcher target architecture' >&2; exit 2 ;; \
		esac; /usr/bin/readelf -hW "$@" \
		| /usr/bin/grep -Eq "Machine:[[:space:]]+$$expected$$"

FORCE:

# GNU Make processes MAKEFLAGS, MAKEFILES, included files, and command-line
# evaluations before any recipe can defend a privilege boundary.  Root Make is
# therefore unsupported; a package manager invokes the fixed activator launcher.
install:
	@echo "root Make install is forbidden; invoke /usr/libexec/grok-bootstrap-package/grok-bootstrap-package-activate directly" >&2
	@exit 2

install-test: $(TARGETS)
	@set -eu; \
		test "$$('/usr/bin/id' -u)" != 0 \
			|| { echo "install-test is nonprivileged only" >&2; exit 2; }; \
		test '$(_CALLER_TEST_MODE_ORIGIN)' = 'command line' \
			&& test '$(_CALLER_TEST_DESTDIR_ORIGIN)' = 'command line' \
			&& test "$${TEST_MODE-}" = 1 \
			&& test -n "$${TEST_DESTDIR-}" \
			|| { echo "install-test requires command-line TEST_MODE=1 and TEST_DESTDIR" >&2; exit 2; }; \
		test '$(_CALLER_TEST_FAIL_AT_ORIGIN)' = undefined \
			|| test '$(_CALLER_TEST_FAIL_AT_ORIGIN)' = 'command line' \
			|| { echo "TEST_FAIL_AT must not come from the environment" >&2; exit 2; }; \
		source_root="$$('/usr/bin/readlink' -f -- '$(BUILD_DIR)')"; \
		if test -n "$${TEST_FAIL_AT-}"; then \
			exec /usr/bin/env -i \
				PATH=/usr/bin:/bin LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \
				GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE=1 \
				/usr/bin/python3 -I -B -S "$$source_root/activate_package.py" \
				--test-root "$$TEST_DESTDIR" --test-stage-from "$$source_root" \
				--test-fail-at "$$TEST_FAIL_AT"; \
		else \
			exec /usr/bin/env -i \
				PATH=/usr/bin:/bin LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \
				GROK_BOOTSTRAP_PACKAGE_ACTIVATOR_TEST_MODE=1 \
				/usr/bin/python3 -I -B -S "$$source_root/activate_package.py" \
				--test-root "$$TEST_DESTDIR" --test-stage-from "$$source_root"; \
		fi
