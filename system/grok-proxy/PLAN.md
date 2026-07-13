# Task Plan

## Context

The deployed Grok proxy already uses one swappable SOCKS endpoint for home-PC and
VPN Gate egress. The new path must use an iPhone without changing host-wide routes,
and three prerequisite safety gaps must be closed first.

## Steps

1. Promote deployed fixes into the canonical tree and preserve a clean source baseline.
2. Add regression tests that demonstrate the injection, ownership, and locking requirements.
3. Implement a separately authenticated userspace Tailscale sidecar and integrate an `iphone` rung.
4. Update CLI help and operational documentation.
5. Mirror runtime files to the deployed directory and run verification.
6. Obtain fresh-context code and security review before delivery.

## Decisions

| Decision | Rationale | Status |
|---|---|---|
| Use a second userspace `tailscaled` | Keeps Grok routing off the VM's primary routes | Accepted |
| Persist sidecar identity under XDG state | Keeps node credentials outside the project/runtime tree | Accepted |
| Put `iphone` after home PCs and before VPN | Prefers stable residential PCs but avoids public VPN when the phone is available | Accepted |
| Require an exclusive session lock | Shared port/state cannot safely serve independent model pins | Accepted |
| Require process-owned listener readiness | Prevents stale or impostor listeners from being marked active | Accepted |
| Provision interactively or via auth-key file | Avoids secrets in argv and does not silently register nodes | Accepted |
| Persist the selected stable Tailscale node ID | Names/IPs are setup selectors only; normal routing cannot drift to a colliding peer name | Accepted |

## Verification Plan

| Check | Command or method | Expected result |
|---|---|---|
| Pre-fix injection regression | `bash tests/test_vpngate_input.sh` | Fails before fix, passes after fix |
| Full regression suite | `bash tests/run.sh` | All tests pass |
| Shell syntax | `bash -n ...` | No errors |
| Python syntax | `python3 -m py_compile socks-netns.py` | No errors; remove generated cache afterward |
| Runtime parity | `cmp` canonical vs deployed | All runtime files identical |
| Live status | read-only Tailscale/Grok proxy status | Existing rung remains intact; phone readiness stated accurately |
