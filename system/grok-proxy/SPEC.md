# Specification

## Goal

Add a phone-only Grok egress rung backed by an isolated userspace Tailscale
daemon selecting the user's iPhone as an exit node, while preserving the stable
loopback SOCKS endpoint, model-aware probing, and fail-closed demotion rules.

## Scope

- In scope:
  - `iphone-setup` provisioning and `--iphone` forced selection.
  - A separate Tailscale state directory, LocalAPI socket, process, and SOCKS listener.
  - Automatic ladder placement after configured home PCs and before VPN Gate.
  - Exit-node online/status checks and model re-probing after every repair.
  - VPN Gate input validation, proxy listener ownership checks, and one-session locking.
  - Regression tests, runtime/canonical synchronization, and README/help updates.
- Out of scope:
  - Enabling or approving the iPhone from this VM.
  - Changing the VM's primary Tailscale daemon or default route.
  - A full cgroup/network-namespace sandbox around the Grok process.
  - Changing xAI account, regional, or service policies.

## Assumptions

- The iPhone runs a current Tailscale app that supports acting as an exit node and is approved as one.
- The userspace sidecar has a separate authenticated tailnet identity.
- Only one `grok-remote` launch owns port 1080 and shared egress state at a time.
- `tailscale`, `tailscaled`, Python 3, `flock`, `ss`, and `jq` are present on the VM.

## Interfaces

- `grok-remote iphone-setup [NODE]`
- `grok-remote --iphone [grok-args...]`
- `GROK_IPHONE_EXIT_NODE`, `GROK_IPHONE_STATE_DIR`,
  `GROK_IPHONE_AUTHKEY_FILE`, and `GROK_IPHONE_HOSTNAME`
- Tailscale 1.98.x userspace networking, SOCKS5 proxy, LocalAPI socket, and exit-node settings.

## Acceptance Criteria

- An unconfigured phone rung is absent from normal selection.
- A configured, online, approved phone can own the stable SOCKS endpoint and pass normal model probes.
- Setup resolves an IP/name selector once and persists the exact stable Tailscale node ID used by normal routing.
- An offline/unapproved phone is rejected without changing primary host routing or falling back direct during demotion.
- Listener readiness proves process ownership, not merely that a port is open.
- Public VPN input cannot inject shell through host/port probing and cannot redirect OpenVPN to a non-global address.
- Concurrent launches and standalone mutating commands are rejected before they change shared state.
- Existing home-PC and VPN selection behavior passes regression checks.

## Verification

- Run a regression that fails on the pre-fix VPN port-injection path.
- Run mocked sidecar lifecycle, listener-ownership, locking, ladder-order, and input-validation tests.
- Run Bash syntax checks and Python bytecode compilation, then remove generated cache files.
- Compare canonical and deployed runtime files byte-for-byte.
- Run read-only live status checks; do not claim a live iPhone route unless the phone is online and approved.

## Risks

- iOS background availability and cellular geolocation remain live-device dependent.
- A loopback SOCKS listener is still cooperative local-process isolation, not a hard sandbox.
- The sidecar adds a persistent tailnet node identity whose state must remain private.
