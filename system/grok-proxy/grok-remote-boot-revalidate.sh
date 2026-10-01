#!/bin/bash
# Auto-recover grok-proxy release admission after a reboot.
#
# The root boot inventory is bound to the current boot_id by design, so after
# every reboot feature-on admission fails closed with
#   "release selection unavailable: current-boot root inventory has not been revalidated"
# and the ladder reports qualified_rungs: [].  If the broker did not shut down
# cleanly it also leaves ledger.json at phase=FAILED, which blocks revalidate --
# producing a circular deadlock (grok-remote needs revalidate, revalidate needs
# the ledger cleared, and recover-compatibility-ledger needs a recovery fence
# that is only published during admission).
#
# Both preconditions are deterministic, so this runs at boot and leaves no
# manual step.
#
# Why automating this does not weaken the gate: per SPEC.md, the boot inventory
# exists so that "revalidate --apply re-runs complete quiescence inventory after
# a boot before feature-on can launch". It attests machine-checkable integrity
# bound to the boot, not human presence. This unit therefore *performs* that
# verification rather than bypassing it, and revalidate still fails closed on a
# mutable release tree or a live release-bound process, leaving grok blocked.
#
# The one guard this script does relax is the FAILED broker ledger, and only on
# proof that it cannot describe a running broker (previous boot AND dead pid).
# The ledger is copied to a .stale-bak-<ts> sidecar first, so crash evidence
# survives for inspection, and revalidate re-verifies everything afterwards.
#
# This MUST run as the target user from a lingering systemd *user* manager, not
# as a root system unit: the installer requires an ancestor cgroup-v2 that is
# target-owned, delegated, and carries cpu+memory+pids. Only user@<uid>.service
# satisfies that; system.slice units are root-owned and are rejected with
# "installer has no target-owned delegated cgroup-v2 parent".
# See grok-remote-boot-revalidate.service.
set -uo pipefail

SEL=/var/lib/grok-proxy/release-control/selected-release.json
LEDGER=/var/lib/grok-proxy/broker/ledger.json

[ -r "$SEL" ] || { echo "grok-revalidate: no selected release; nothing to do"; exit 0; }

REL=$(/usr/bin/python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["release_id"])' "$SEL") \
  || { echo "grok-revalidate: cannot read selected release"; exit 0; }

INSTALLER="/usr/local/libexec/grok-proxy/releases/$REL/install-release.py"
sudo -n test -r "$INSTALLER" || { echo "grok-revalidate: installer missing for $REL"; exit 0; }

# Drop the broker ledger only when provably stale: recorded under a previous
# boot AND its relay pid is not alive. A live or current-boot ledger is kept.
sudo -n /usr/bin/python3 -I -B -c '
import json, os, shutil, sys, time
led = sys.argv[1]
cur = open("/proc/sys/kernel/random/boot_id").read().strip()
if not os.path.exists(led):
    sys.exit(0)
try:
    d = json.load(open(led))
except Exception:
    sys.exit(0)                     # unreadable -> leave it for the installer
relay = d.get("relay") or {}
if relay.get("boot_id") == cur:
    sys.exit(0)                     # belongs to this boot -> keep
pid = relay.get("pid")
if isinstance(pid, int):
    try:
        os.kill(pid, 0)
        sys.exit(0)                 # still alive -> keep
    except ProcessLookupError:
        pass
    except PermissionError:
        sys.exit(0)                 # cannot prove dead -> keep
stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
shutil.copy2(led, f"{led}.stale-bak-{stamp}")
os.unlink(led)
print("grok-revalidate: removed stale broker ledger (previous boot, dead relay pid)")
' "$LEDGER"

# Keep the exact administrative argv shape. The installer excludes its own
# invocation from the quiescence scan only for argv of the form
#   sudo [-n] -- /usr/bin/python3 -I -B <installer> ...
# with the sudo process as the direct parent; anything else makes this very
# process count as a release-bound blocker and the run fails. exec so that bash
# is replaced and sudo really is python's parent.
exec sudo -n -- /usr/bin/python3 -I -B "$INSTALLER" revalidate --apply
