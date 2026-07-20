# grok-proxy — run grok through an egress that actually offers the model you want

grok.com can offer different model menus by the region of the requesting IP. `grok-remote` walks
trusted routes in configured priority order, takes the first healthy route with a usable model
catalog, then holds it up for as long as grok runs and fails over underneath the session when one
dies.

```
  home PC over Tailscale  >  registered iPhone/iPad exit nodes  >  VPN Gate servers ...  [direct = selection fallback]
           |                        |                    |
      ssh -D binds          userspace tailscaled   socks-netns.py binds
     127.0.0.1:1080          binds the same port    (egress in netns 'grokvpn')
```

Two ideas hold this together.

**Compatibility lane: one endpoint, swappable underneath.** Every rung presents grok with the *same* SOCKS5 endpoint,
`127.0.0.1:1080`. That is what lets a rung be replaced without restarting grok. When a rung dies
the port vanishes for a few seconds; grok fails closed, retries silently for about 5.5 minutes,
then resumes the in-flight turn. Any swap that lands inside that window never reaches the
session — measured: a home PC killed mid-generation was replaced in ~5s, grok froze for ~25s and
then finished the same turn, exit 0, with no error shown to the user.

The managed multi-session lane keeps a committed public listener bound and swaps
only its private backend generation; it revokes old streams during cutover so
clients retry through the newly qualified generation rather than seeing
probationary traffic. Once an installer-attested default profile is active,
bare `grok-remote` uses this lane without caller environment or route injection.

**"Works" means the preferred route can actually serve the session — no model name is hardcoded.**
grok-remote measures what this VM is offered with *no* tunnel (the **baseline**) for diagnostics
and direct-fallback qualification. It then takes the first configured remote rung that passes
country policy, reaches the Grok model API, and offers the required model (or any nonempty valid
catalog when no model is pinned). An equal catalog is still useful routing: a healthy Windows home
route is selected immediately instead of being discarded while unavailable phones and VPNs are
tried.

This is deliberately *not* a version comparison. The id space holds `grok-4.20-0309-reasoning`,
`grok-420-computer-v0`, `grok-build` and `grok-composer-2.5-fast`, and carries no release date, so
"pick the highest number" would cheerfully crown `grok-420-computer-v0` the newest chat model.
The baseline still identifies and reports what a route adds, but a catalog delta is not an
admission requirement. This avoids turning a newly global model into a reason to reject every
healthy preferred route.

Each rung is probed by exit country first (free, and rejects a route denied by the frozen
country policy), then by a fresh `grok models` request through that rung — one API round-trip,
no inference tokens.

**And the unlocked model is the one you actually get.** Left alone, grok keeps using its own
default (`grok-build`) even when a better model is on the menu, so unlocking one is not the same as
using it. grok-remote launches grok on the model you want — and **remembers it**, so you are not
asked twice:

```
[egress] egress: local:arch  (grok.com will see 203.0.113.7)
[egress] model: grok-4.5 (remembered — --pick-model to change)
```

The remembered-menu behavior below describes the compatibility lane.  An
active managed profile instead freezes one model: omitting `-m` uses that
model, the same explicit `-m` is accepted, and changing models requires a new
candidate, qualification, and activation.

- **One model unlocked** → it is used. Nothing to ask.
- **Several unlocked, first time** → you get a menu once; your pick is saved to `.model.choice`.
- **Same models next time** → your pick is reused silently.
- **A model you have never been offered appears** → you are asked again, with your current choice
  as the default, so Enter keeps it. Picking `0` means "let grok decide", and that is remembered
  too — it will not nag you.
- **Your saved model stops being offered** by the current egress → you are asked again.
- **Headless** (`-p`, `--prompt-file`, no TTY) → never prompts. It uses your saved model if this
  egress still offers it, and otherwise injects nothing rather than guessing — the menu stays owed
  until you next run interactively.
- **`-m` / `--model=` you passed yourself** → never overridden, and recorded as your new choice.
  This is the simplest way to change your mind: `grok-remote -m grok-5`.
- **Subcommands** (`grok-remote models`, `login`, …) → nothing injected.

Because the session is pinned to one model, the *failover* is pinned to it too: neither a demotion
nor a same-rung repair will settle on an egress that no longer offers it (a reconnected VPN can
surface in a different region, so a repaired rung is re-probed, not just checked for liveness).
When nothing serves the model, grok-remote tears the egress down and keeps retrying from the top,
so grok fails closed and waits rather than being pointed at a wrong-region exit — the moment a rung
that serves your model appears, it is picked up and grok resumes.

grok-remote never writes grok's own `[models] default` in `~/.grok/config.toml` — doing so would
break a plain `grok` run outside the tunnel, where the unlocked model does not exist.

> **Invariant: a *demotion* never lands on `direct`.** Dropping a live remote session to direct
> would silently change its route and unmask the VM's real region. Direct is considered only during
> initial selection, after every configured remote rung is unavailable or unusable, and only when
> the direct catalog can serve the request.

## Files

| File | Runs on | Purpose |
|------|---------|---------|
| `grok-remote` | this VM | front end: pick an egress, launch grok through it, supervise it |
| `egress.sh` | this VM | the ladder, the probes, the watchdog (sourced by `grok-remote`; also a CLI) |
| `socks-netns.py` | this VM | SOCKS5 server that binds the port in the host namespace but egresses from the VPN namespace |
| `vpngate-connect.sh` | this VM | VPN Gate: fetch servers, connect one in netns `grokvpn`, walk to the next on failure |
| `hosts.conf` | this VM | home egress PCs, tried top to bottom |
| `id_grokproxy[.pub]` | this VM | dedicated SSH key (public key is baked into the setup scripts) |
| `~/.local/state/grok-proxy/iphone/` | this VM | private identity and LocalAPI state for the isolated iPhone sidecar |
| `~/.local/state/grok-proxy/profiles/` | this VM | owner-only, content-addressed managed multi-session profiles |
| `/var/lib/grok-proxy/release-control/active-profile.json` | this VM | root-owned public activation binding for the default profile |
| `/var/lib/grok-proxy/release-control/{qualified-rungs,profile-activations}/` | this VM | root-owned per-release rollback catalogs, revalidated before restoration |
| `dist/setup-grok-proxy-windows.bat` | Windows PC | enable OpenSSH server + authorize this VM's key |
| `dist/setup-grok-proxy-arch.sh` | Arch PC | enable sshd + authorize this VM's key |

## Source, backup, and runtime ownership

The Grok implementation has four deliberately separate roles:

1. `~/grok-proxy` is the canonical editable authoring and backup-capture source.
   It also contains private configuration and generated runtime state that are
   classified separately by `MANIFEST.yaml`.
2. `coding-system-rebuild/system/grok-proxy` is the sanitized public backup
   snapshot. Capture replaces this snapshot from the complete allowlisted public
   source and prunes stale public paths, while preserving repository-local
   `.planning` and `.learnings` directories.
3. The root-owned immutable release directories are the only production runtime
   source. `~/.local/bin/grok-remote` is a root-owned convenience selector; the
   selected immutable payload independently self-admits against the coherent
   user/root selection. Exactly that user release is readable (`0555`); retained
   inactive user releases are archived root-only (`0500`).
4. The separately packaged native bootstrap, production public key, signed
   dispatcher store, and administrative selector form the pre-import update
   authority. Candidate source and ordinary release installation cannot create,
   rotate, or replace this trust anchor.

Run `grok-remote` through the installed command. Direct execution of
`~/grok-proxy/grok-remote`, a repository checkout, or a standalone editable
`egress.sh` is refused for normal production use. A fresh restore populates only
missing allowlisted public source paths. If any existing managed path differs,
restore stops without overwriting it; merge authoring changes explicitly first.
The administrative signing workflow stages a closed dispatcher from the
reviewed public closure, and the native root-owned verifier executes only the
signed application selected by the root-owned bootstrap selector. The normal
install workflow reconciles `~/grok-proxy` for capture/restore parity but never
executes that editable tree as root. The repository copy is the sanitized
restore/backup source, not a second live implementation.

Private files such as `hosts.conf`, `known_hosts`, and `id_grokproxy`, plus
model choices, sidecar state, locks, sockets, and tunnel state, never enter the
public snapshot. They remain encrypted-private or regenerated according to the
manifest.

## One-time setup: home PCs

**1. On each home PC**, run its setup script:

- Windows: copy `dist/setup-grok-proxy-windows.bat` over and double-click it
  (it self-elevates to Administrator).
- Arch Linux: copy `dist/setup-grok-proxy-arch.sh` over and run
  `bash setup-grok-proxy-arch.sh`.

Each script prints a ready-made `hosts.conf` line, e.g. `windows  100.x.y.z  YourUser  22`.

**2. On this VM**, put the printed `hosts.conf` line(s) into
`~/grok-proxy/hosts.conf` and the separately printed SSH host-key line(s) into
`~/grok-proxy/known_hosts` (`chmod 600` both files). Verify the key text over a
channel independent of the first SSH connection. If `known_hosts` is absent,
both compatibility and managed home routing fall back to `accept-new`
trust-on-first-use; that is a convenience fallback, not protection from
interception of the first connection.

## One-time setup per iPhone or iPad

The iOS rungs use a **second, userspace-only Tailscale identity** on this VM. It has its own
state, LocalAPI socket, and loopback SOCKS listener. It does not select an exit node on the VM's
primary Tailscale daemon and does not change the VM's default route.

1. In the Tailscale app on each iPhone or iPad, enable **Run as Exit Node**. Keep Tailscale current; iOS
   exit-node support requires a recent app. See Tailscale's official
   [iOS exit-node instructions](https://tailscale.com/docs/features/exit-nodes?tab=ios).
2. In the Tailscale admin console, approve each device's advertised exit route. If this tailnet has
   custom grants or ACLs, also permit this VM's sidecar identity to use exit nodes.
3. Stop any active Grok egress, then register each device once while it is available:

```bash
grok-remote stop
grok-remote iphone-setup                 # auto-detects when exactly one iOS peer exists
# or, if detection is ambiguous:
grok-remote iphone-setup iphone-xr        # IP, DNS name, or stable node ID
grok-remote iphone-setup ipad-pro --label ipad-pro
grok-remote iphone-list                   # priority, availability, and qualification
grok-remote iphone-reorder ipad-pro iphone-xr
```

The setup command opens Tailscale's normal interactive login. For unattended enrollment, put a
Tailscale auth key in a mode-`600` file and set `GROK_IPHONE_AUTHKEY_FILE` to that file; the key is
passed using Tailscale's `file:` form and never placed in the process arguments. Normal
`grok-remote` runs never attempt login and will skip a sidecar that has not completed setup.

Setup commits only after the selected device is online as an approved exit node and exact sidecar
teardown succeeds. The private registry stores its Tailscale stable node ID, so ordinary runs do
not need `iphone-setup` again. Repeating setup for the same device is an order-preserving no-op;
the single legacy `iphone` key is upgraded to its DNS-derived key on the next successful setup.
Use `--label KEY` when Tailscale does not expose a unique DNS name. `iphone-remove KEY` forgets
one device; it does not modify that device's Tailscale configuration.

## Daily use

```bash
grok-remote                  # managed when valid; compatibility if absent/stale; invalid current state blocks
grok-remote doctor --json    # read-only managed-profile readiness
grok-remote status           # active rung, the IP grok.com sees, and the remembered model
grok-remote ip               # just that IP
grok-remote --host arch      # force one home PC when it offers your selected model
grok-remote --iphone         # try only registered iOS devices, in priority order
grok-remote --ios ipad-pro   # force one exact device; never substitute another
grok-remote --vpn            # skip direct and the home PCs, start on VPN Gate
grok-remote --no-direct      # never use direct, even if it would work
GROK_MULTI_SESSION=0 grok-remote --pick-model  # compatibility: reopen its model menu
GROK_MULTI_SESSION=0 grok-remote -m grok-5     # compatibility: change remembered model
grok-remote recover          # reconcile a dead managed epoch exactly
grok-remote stop             # tear the egress down
```

With an active managed profile, `--pick-model` is intentionally rejected and
an explicit `-m` must equal the frozen model.  To change that model
permanently, create, qualify, and activate a new profile as described below.

With no active managed profile, or with the explicit
`GROK_MULTI_SESSION=0` escape, compatibility mode remains a verified singleton:
one mutating
`grok-remote` command owns the legacy proxy/state at a time. A second launch,
`ip`, setup, or `stop` command fails fast while that lock is held; `status`
remains read-only.

The exact one-argument `recover` command is a reserved crash-cleanup interface,
not a Grok prompt. It remains reachable when the variable is absent or exactly
`0`/`1`, including while an installer deny is active. Other present values
(including empty, `true`, `01`, and `2`) remain literal legacy compatibility
and receive no managed-recovery or deny-bypass authority.

Automatic discovery and explicit selection share the same route-usability
checks. Automatic mode walks the configured home-PC, ordered iOS-device, and VPN priority
and takes the first healthy route with a usable catalog, even when direct has
the same models. `--host LABEL` and `--ios KEY` bind the session to one exact
route; `--iphone` is the iOS family and may move to the next registered device.
They require the explicit, environment-pinned, or
nonempty remembered model when one exists. With no concrete preference, a
forced model picker or routed `models` command receives the route's complete
valid catalog. An intentionally empty remembered choice continues to mean “let
Grok decide.” The exact-route watchdog repairs or reacquires only the named
host or exact iOS device and never silently demotes an exact session to
another home PC, iOS device, VPN, or direct. The iOS family spends at most 30
seconds on one device and 120 seconds total before the automatic ladder can continue. If exact teardown cannot
prove that the old control master/listener stopped, the ownership record is
retained and no replacement is raised over it. Home-host startup records the
validated cleanup destination before OpenSSH starts, so publication failure is
effect-free and an uncertain startup can still be stopped exactly. It also
refuses to unlink an unexplained SSH control path. Route teardown is an
aggregate transaction: the validated owner is stopped first, local/phone/VPN
cleanup are all attempted, and a bounded second pass proves shared-port
absence after cross-provider listeners disappear. The ownership state changes
to empty only after that final pass succeeds.
Automatic selection, watchdog repair/demotion, stale replacement, `ip`, the
standalone selector, forced-VPN failure cleanup, and `stop` all use that rule;
selection itself refuses to start over nonempty ownership state. A mode-0600
`.egress.recovery-required` marker covers transition windows in which state may
temporarily be empty; a later command performs cleanup only while it exists.
Fresh startup first reconciles ownerless SSH, sidecar, and VPN residue. SSH
cleanup consumes a destination only from a validated `local:*` record, so an
iPhone record can never direct an OpenSSH control command. `iphone-setup` uses
the same owned transaction and cannot report success if final sidecar teardown
is uncertain. It refuses a valid selected route and asks for `grok-remote stop`
instead of silently replacing it; only pending or malformed ownership enters
recovery. Warm multi-session handoff completes any pending compatibility
recovery before it proceeds, unless the authenticated broker fences a live
legacy VPN ledger.

### One-time managed-profile activation

Remove any persistent `export GROK_MULTI_SESSION=1` left from the opt-in era.
The managed activation is now the default authority; keeping that export would
continue to force the release-sensitive migration path whenever no activation
for the selected release is available.  Use `GROK_MULTI_SESSION=0` only on an
individual command that must use compatibility mode.

Create a private candidate after installing the release. The command prints
only public identifiers and readiness; the frozen endpoints remain in the
mode-0600 content-addressed profile:

```bash
grok-remote profile-create --json
```

Record the printed `<release_id>`, `<profile_sha256>`, and `missing_rungs`.
Qualify a newly installed release once with the two fixed release gates:

Invoke the installer exactly as shown. The quiescence inventory recognizes only
this concrete Python command and its immediate `sudo [ -n ] --` monitor as the
administrative pair. Both processes must match in the same inventory pass;
shell or `env` wrappers inserted between `sudo` and Python, and any additional
release-bound cwd, executable, or path-valued argument, remain blockers. An
outer invoking shell is not a release consumer merely because opaque `-c` text
mentions the installer: new consumers are serialized behind the selection lock,
the deny is durable before this command returns, and every process actually
holding a release path is still inventoried.

```bash
RELEASE_ID='<release_id>'
[[ $RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$RELEASE_ID/install-release.py"
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" begin-release-qualification \
  --release-id "$RELEASE_ID" \
  --apply
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" canary-exec \
  --qualification-step load32 \
  --apply
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" canary-exec \
  --qualification-step fault-recovery \
  --apply
```

Then run this profile-bound sequence once for each concrete desired
`<missing_rung>` (only one rung canary may be active at a time):

```bash
RELEASE_ID='<release_id>'
[[ $RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$RELEASE_ID/install-release.py"
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" begin-rung-canary \
  --release-id "$RELEASE_ID" \
  --rung '<missing_rung>' \
  --profile-sha256 '<profile_sha256>' \
  --apply
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" canary-exec \
  --qualification-step real-pair \
  --apply
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" promote-rung \
  --apply
```

The profile digest makes the installer derive the route, full contract,
projected contract, Grok, and model bindings; do not reconstruct those values
from ambient configuration. Promotion writes schema-9 terminal evidence that
binds both the original full-contract digest and the conservative per-rung
qualification digest. The same projected rung may be reusable across automatic
and forced selection, but not across a relevant endpoint, policy, helper,
proxy-release, model, or Grok-binary change.

After at least the candidate's readiness minimum is promoted, activate the
printed profile digest and verify it:

```bash
RELEASE_ID='<release_id>'
[[ $RELEASE_ID =~ ^[0-9a-f]{64}$ ]] || exit 2
GROK_INSTALLER="/usr/local/libexec/grok-proxy/releases/$RELEASE_ID/install-release.py"
sudo -- /usr/bin/python3 -I -B \
  "$GROK_INSTALLER" activate-profile \
  --profile-sha256 '<profile_sha256>' \
  --apply
grok-remote doctor --json
```

The activation JSON includes `profile_transition`. `activated` is the normal
result. `activated-history-degraded` means the live pointer committed but its
rollback archive could not be refreshed. `activated-durability-uncertain`
means the pointer rename committed but its parent-directory fsync failed; this
is reported separately from a pre-commit failure. No later release switch is
allowed to proceed unless it first re-snapshots that exact active binding.
`ready` means
every frozen rung is promoted. `degraded` means the minimum is
met and bare multi-session use is safe, but the listed optional rungs are not
eligible. `blocked` and `unconfigured` return exit 2 and never start egress.
An update is staged by creating and qualifying a new candidate before the root
activation pointer is replaced, so interruption leaves the prior activation
bytes intact. Old evidence is not silently converted when the qualification
schema changes.

After activation, simultaneous calls need no feature flag:

```bash
grok-remote --single "first task"
grok-remote --single "second task"
grok-remote status
```

The supervisor accepts concurrent leases only when their concrete model
and full typed routing contract match. They share one committed loopback SOCKS
frontend and one provider generation, while each Grok child receives a distinct
leader socket and session identity. A different model, route mode, home-host
snapshot, phone identity, helper release, timeout, port, or resource limit is
rejected before it can mutate the active route. Once the last lease exits, the
supervisor proves exact cleanup and releases the compatibility fence. Setup,
stop, install, rollback, and other mutating maintenance remain interlocked with
the active generation. In the managed lane, an explicit `-m`/`--model` must
equal the frozen profile model and does not become new authority. Only the
explicit compatibility lane maintains the legacy remembered-model choice.

Release recovery is ledger-driven. Once an immutable target user/root release
pair has been published, `install-release.py resume --apply` can finish without
the original source checkout. If interruption occurs before publication, retry
the install from the exact frozen source tree or abort to the recorded prior
release; `resume` cannot recreate unpublished bytes. An upgrade may migrate the
old inactive `/var/lib/grok-vpngate` artifacts only during an authenticated
install CANARY with current-host passing evidence for the prior release. Any
active or ambiguous OpenVPN, namespace, tun, listener, cgroup, FIFO, link, or
mount state fails closed. Keep an independent root-only archive until the new
release, rollback, and reinstall have all been verified.
The later public warm-handoff step never deletes root artifacts; it only proves
the installer left them absent before clearing user-side legacy state.
Release switching snapshots the exact selected schema-9 rung records and
active profile into per-release catalogs. Upgrade or rollback restores them
only after revalidating host identity, terminal evidence, the private profile,
pinned Grok bytes, and readiness. A missing or invalid catalog degrades to the
remaining valid rungs or compatibility instead of silently authorizing stale
state. If the still-current root pointer is an exact dormant binding for the
rollback target, the installer revalidates it and rebuilds missing history;
`resume` and `abort` report the same `profile_transition` field as install and
rollback. Invoking the immutable release payload directly applies the same managed
activation and current-boot-inventory decisions as the installed entrypoint.
Fixed qualification records bind the exact generated user and broker gate
digests. A changed gate generator therefore cannot reuse stale load/fault
results even if runtime files produce the same release ID. Version 1 has no
supported reset for a completed qualification directory, so that same-ID state
fails closed rather than becoming freshly qualifiable. Keep the exact installer
bytes frozen for a reproducible live install, qualification, rollback, and
reinstall exercise; a future reset/migration workflow is required before
supporting changed-generator same-ID requalification.
During real-pair teardown, the captured supervisor can finish naturally between
two liveness samples, or the guarded pair can begin draining before destructive
authority is renewed. The latter path closes the qualification pause first and
is passive-only: it may stop the verifier's exact wrappers but cannot signal the
supervisor or invoke recovery. Convergence requires a same or already removed
fence, the complete user/root/listener/cgroup clean proof, and a separate bounded
absence proof for the captured supervisor identity. A replacement or malformed
fence still fails closed. Cleanup after an earlier primary failure retains both
facts in a closed stage-specific diagnostic code without exposing dynamic text.
Post-repair status polling treats only already-contained transient helper failures
as unavailable samples, and the following recovery-authority scan has its own
closed checkpoint.

## How failure is handled

The watchdog checks the active rung every 10s (cheap: `ssh -O check`, or the tun plus the proxy
pid), and every 6th cycle proves real egress with one HTTP GET — a tunnel can be up while the far
end blackholes. On failure it repairs the *same* rung twice, and only then demotes:

```
home PC dies  ->  rebuild (x2)  ->  still dead?  ->  first registered iOS device
iOS A dies    ->  restart A (x2)  ->  still dead?  ->  iOS B  ->  VPN Gate server #1
VPN #1 dies   ->  one grace cycle  ->  VPN Gate server #2  ->  #3 ...
```

The compatibility watchdog model-reprobes the active iOS rung during repair and
periodic deep checks. The managed supervisor model-qualifies every candidate
at admission and repair, while its periodic watchdog checks exact process and
exit identity. Thus a managed phone whose egress changes is repaired and
requalified, but a model-catalog change behind an unchanged exit IP is not
proactively detected until traffic fails and triggers repair.

Before any compatibility repair raises a replacement, teardown of the current
rung must succeed. A failed teardown retains the cleanup identity and blocks
repair or demotion. `stop` likewise reports failure without clearing route
state when any component cleanup is incomplete, so a later recovery attempt
never has to guess what may still own the listener.

Failed VPN servers are blacklisted for the session and never handed out again; the candidate list
is refetched once every server on it has been burned. Once demoted, the ladder **stays** demoted
for the rest of the session — a home PC waking up does not trigger a switch back, because changing
the exit IP mid-conversation risks bot-flagging and re-auth.

### Why the VPN rung needs `socks-netns.py`

The VPN must stay confined to a network namespace so it cannot hijack routing for Tailscale, the
OpenClaw gateway, or your SSH session. But grok has to live *outside* that namespace to be
reachable at a stable local port. `socks-netns.py` bridges the two: it binds the listening socket
in the host namespace and only then enters `grokvpn`, so grok can reach `127.0.0.1:1080` while
every outbound connection *and every DNS lookup* leaves through the tun.

That preserves the kill switch. When the tun dies the namespace has no route left, outbound
connects fail, and nothing falls back to the host route — verified: with the namespace's route
deleted, requests through the proxy fail rather than leaking out of the host.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `GROK_MULTI_SESSION` | managed default | absent selects a current managed profile; `0` explicitly selects compatibility; `1` remains a qualification/migration input; any other present value retains literal legacy compatibility behavior |
| `GROK_REQUIRE_MODEL` | *(unset)* | pin one model instead of the baseline rule, e.g. `grok-5`. Unset = accept any rung that unlocks something |
| `GROK_PROXY_PORT` | `1080` | the shared loopback SOCKS frontend used by the active generation |
| `GROK_RUNG_RETRIES` | `2` | repairs of the same rung before demoting |
| `GROK_WATCH_INTERVAL` | `10` | seconds between liveness checks |
| `GROK_DEEP_EVERY` | `6` | prove real egress every Nth check |
| `GROK_VPN_MAX_TRIES` | `6` | VPN Gate servers to walk before giving up |
| `GROK_ALLOW_DIRECT` | `1` | set `0` to never probe the direct rung |
| `GROK_MODEL_PROMPT` | `1` | set `0` to never show the model menu (use the saved choice only) |
| `GROK_IPHONE_EXIT_NODE` | *(unset)* | setup-only selector when no identity is saved; normal routing uses the stable node ID pinned by `iphone-setup` |
| `GROK_IPHONE_STATE_DIR` | `~/.local/state/grok-proxy/iphone` | private state/socket/log directory for the userspace sidecar |
| `GROK_IPHONE_AUTHKEY_FILE` | *(unset)* | auth-key file used only by `iphone-setup`; never an inline secret |
| `GROK_IPHONE_HOSTNAME` | `grok-iphone-relay` | tailnet hostname for the sidecar identity |
| `GROK_BLOCKED_CC` | `CN IR KP TM VE` | frozen all-rung country deny; an explicit override is preserved in the contract |
| `VPNGATE_COUNTRIES` | — | force an ordered country list, e.g. `"VN JP"` |

State kept in this directory: `.model.choice` (your model), `.model.seen` (the menu you were last
offered), `.baseline.models`, `.unlocked.models` (the selected route's eligible models: normally
the automatic baseline delta, or the exact/full catalog admitted for a forced host or iOS device),
`.egress.state`. During a compatibility transition,
`.egress.recovery-required` is a generated crash-recovery marker and is removed
only after exact cleanup publishes empty state. The iPhone's Tailscale identity
is deliberately outside the project tree at `~/.local/state/grok-proxy/iphone`; treat
`tailscaled.state` and `devices.json` as private credentials/topology and do not publish them.

Compatibility mode applies a private creation mask to every Grok model probe
and to the interactive launch.  This keeps Grok's regenerated shared model
cache non-group-writable even when the calling shell uses a cooperative umask,
including when the watchdog performs a later deep route check, so subsequent
multi-session verification can safely consume it.

## Caveats

- Keep the chosen home PC **awake**. A sleeping PC is a dead rung; you will land on VPN Gate.
- Keep Tailscale active on the selected iPhone or iPad. iOS suspension, loss of coverage, Low Power Mode, roaming,
  or switching between Wi-Fi and cellular can interrupt or change its public egress. The watchdog
  repairs or demotes; it never treats peer-online status alone as proof that the model still works.
- Traffic is `socks5h`, so DNS resolves at the egress. There is no DNS leak on any rung.
- The shared TCP SOCKS endpoint is loopback-only but has no cross-UID peer
  authentication. Multi-session v1 therefore supports only a single-tenant
  host where every local account able to connect to loopback is trusted; another
  local UID could otherwise consume the route or its bounded stream capacity.
- VPN Gate servers are shared/datacenter IPs, and grok.com may bot-flag them even when the region
  is right — prefer the home-PC path. Their country labels are also approximate (a "VN" entry may
  exit in JP), so every candidate must still pass the fresh route-scoped model probe.
- Service availability and country policy can change. This routes your own account's Grok traffic
  through a selected egress; review xAI's current terms before relying on it.
- Install path matters: `ssh -M` appends a 17-char suffix to the control socket and a Unix socket
  path caps at ~108 chars. `~/grok-proxy` is fine; a deeply nested directory is not.
- `grok --debug-file` writes your OAuth bearer token to the log in cleartext. Treat those files as
  secrets.

## What is verified, and what is not

Verified end-to-end on this VM before this addition: the ladder's selection, repair and demotion; the VPN candidate
cursor and blacklist; `socks-netns.py` proxying, in-namespace DNS, privilege drop, fail-closed
behaviour and recovery; a real grok session surviving a live rung swap without restarting; and the
baseline rule — including that it skips a home PC which is itself region-blocked, falls back to
direct when routing gains nothing, refuses to *demote* into direct, treats a globally-released
model as baseline rather than an unlock, and is not fooled by `grok-420-computer-v0`.

Model hand-off is verified against the real binary from both sides: a valid unlocked model launches
grok on it and answers, and a deliberately bogus one is rejected by grok itself
(`Couldn't set model ...: unknown model id`) — which is what proves the `-m` genuinely lands rather
than being silently dropped.

Model memory is verified too: asked once, reused silently, asked again only when a genuinely new
model appears (Enter keeps the current one), asked again when a saved model stops being offered,
never prompting in a headless run, and never silently dropping a saved model just because something
new showed up.

The failover pin is verified on both paths: with a home PC serving the model and every VPN exit
lacking it, the watchdog refuses to settle on the VPN — the demote path rejects it and the
same-rung repair path re-probes and rejects it too — tears down to fail closed rather than pointing
grok at a wrong-region exit, leaves no phantom rung in its state, and auto-recovers the instant a
VPN exit that serves the model appears.

The iOS implementation is verified with a mocked userspace `tailscaled` and LocalAPI: separate state
and socket arguments, exact stable-ID selection, ordered multi-device registry, exact listener ownership,
setup gating, typed ladder placement, lock-FD isolation, wrong-node rejection, and fail-closed exact selection all pass.
VPN Gate metadata validation, proxy-environment clearing, compatibility locking,
and managed same-contract admission have dedicated regressions too.

**A live device must still be available for its production canary:** advertising and admin approval,
the sidecar's live tailnet login, cellular public egress, locked-screen longevity, and a real
model list/invocation cannot be inferred from deterministic tests. A mocked sidecar proves the
wrapper contract; it does not prove iOS availability or carrier behavior.

Because nothing is pinned to a model name, there is no longer anything to update when xAI ships a
new flagship — the first run through a working tunnel will simply report what it unlocked.
