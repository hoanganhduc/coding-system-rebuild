# grok-proxy — run grok through an egress that actually offers the model you want

grok.com can offer different model menus by the region of the requesting IP. When a remote VM's
direct egress lacks a model that a trusted home connection offers, `grok-remote` picks the best
qualifying egress, then holds it up for as long as grok runs and fails over underneath the session
when one dies.

```
  home PC over Tailscale  >  iPhone exit node  >  VPN Gate servers ...  [direct = selection fallback]
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

The opt-in multi-session lane keeps a committed public listener bound and swaps
only its private backend generation; it revokes old streams during cutover so
clients retry through the newly qualified generation rather than seeing
probationary traffic.

**"Works" means it unlocks a model you cannot otherwise get — no model name is hardcoded.**
The direct connection reaches grok.com perfectly well; it is just handed a smaller menu. So
grok-remote measures what this VM is offered with *no* tunnel (the **baseline**), then takes the
first rung that offers something the baseline does not have, and tells you what that was.

This is deliberately *not* a version comparison. The id space holds `grok-4.20-0309-reasoning`,
`grok-420-computer-v0`, `grok-build` and `grok-composer-2.5-fast`, and carries no release date, so
"pick the highest number" would cheerfully crown `grok-420-computer-v0` the newest chat model.
What the region gate hides is, by definition, whatever direct cannot see — so that is what gets
tested. It never goes stale when xAI ships the next flagship, and it self-corrects: a model that
becomes available *everywhere* simply joins the baseline instead of looking like an unlock.

Each rung is probed by exit country first (free, and rejects the EU / X-banned block outright),
then by `grok models` through that rung — one API round-trip, no inference tokens.

**And the unlocked model is the one you actually get.** Left alone, grok keeps using its own
default (`grok-build`) even when a better model is on the menu, so unlocking one is not the same as
using it. grok-remote launches grok on the model you want — and **remembers it**, so you are not
asked twice:

```
[egress] egress: local:arch  (grok.com will see 203.0.113.7)
[egress] model: grok-4.5 (remembered — --pick-model to change)
```

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

> **Invariant: a *demotion* never lands on `direct`.** The rung being abandoned had unlocked
> models, so dropping to direct would silently downgrade the session *and* unmask the VM's real
> region — the exact thing this tool exists to prevent. Direct is taken only at selection time, and
> only when no rung unlocks anything at all, i.e. when a tunnel would buy you nothing.

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
| `dist/setup-grok-proxy-windows.bat` | Windows PC | enable OpenSSH server + authorize this VM's key |
| `dist/setup-grok-proxy-arch.sh` | Arch PC | enable sshd + authorize this VM's key |

## Source, backup, and runtime ownership

The Grok implementation has three deliberately separate roles:

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

Run `grok-remote` through the installed command. Direct execution of
`~/grok-proxy/grok-remote`, a repository checkout, or a standalone editable
`egress.sh` is refused for normal production use. A fresh restore populates only
missing allowlisted public source paths. If any existing managed path differs,
restore stops without overwriting it; merge authoring changes explicitly first.
The install workflow stages runtime bytes from the reconciled canonical
`~/grok-proxy` tree. The repository copy is the sanitized restore/backup source,
not a second live implementation.

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
both compatibility and opt-in home routing fall back to `accept-new`
trust-on-first-use; that is a convenience fallback, not protection from
interception of the first connection.

## One-time setup: iPhone exit node

The phone rung uses a **second, userspace-only Tailscale identity** on this VM. It has its own
state, LocalAPI socket, and loopback SOCKS listener. It does not select an exit node on the VM's
primary Tailscale daemon and does not change the VM's default route.

1. In the Tailscale app on the iPhone, enable **Run as Exit Node**. Keep Tailscale current; iOS
   exit-node support requires a recent app. See Tailscale's official
   [iOS exit-node instructions](https://tailscale.com/docs/features/exit-nodes?tab=ios).
2. In the Tailscale admin console, approve the phone's advertised exit route. If this tailnet has
   custom grants or ACLs, also permit this VM's sidecar identity to use exit nodes.
3. Stop any active Grok egress, then enroll the sidecar and pin the phone:

```bash
grok-remote stop
grok-remote iphone-setup                 # auto-detects when exactly one iOS peer exists
# or, if detection is ambiguous:
grok-remote iphone-setup 100.x.y.z       # phone's Tailscale IP, DNS name, or stable node ID
```

The setup command opens Tailscale's normal interactive login. For unattended enrollment, put a
Tailscale auth key in a mode-`600` file and set `GROK_IPHONE_AUTHKEY_FILE` to that file; the key is
passed using Tailscale's `file:` form and never placed in the process arguments. Normal
`grok-remote` runs never attempt login and will skip a sidecar that has not completed setup.

Setup writes its readiness marker only after the selected phone is online as an approved exit
node, then replaces the setup selector with Tailscale's exact stable node ID. Normal routing uses
only that pinned ID. If setup reports that enrollment succeeded but the phone is not usable,
finish steps 1–2 and rerun `grok-remote iphone-setup`.

## Daily use

```bash
grok-remote                  # compatibility mode: one session owns the egress
grok-remote status           # active rung, the IP grok.com sees, and the remembered model
grok-remote ip               # just that IP
grok-remote --host arch      # force one home PC
grok-remote --iphone         # force the configured phone; never falls back to direct
grok-remote --vpn            # skip direct and the home PCs, start on VPN Gate
grok-remote --no-direct      # never use direct, even if it would work
grok-remote --pick-model     # re-open the model menu even if nothing has changed
grok-remote -m grok-5        # use this model, and remember it from now on
grok-remote stop             # tear the egress down
```

The default compatibility mode remains a verified singleton: one mutating
`grok-remote` command owns the legacy proxy/state at a time. A second launch,
`ip`, setup, or `stop` command fails fast while that lock is held; `status`
remains read-only.

Set the opt-in flag on every participating launch to share one qualified
route between simultaneous Grok processes:

```bash
GROK_MULTI_SESSION=1 grok-remote -m grok-build --single "first task"
GROK_MULTI_SESSION=1 grok-remote -m grok-build --single "second task"
GROK_MULTI_SESSION=1 grok-remote status
```

The opt-in supervisor accepts concurrent leases only when their concrete model
and full typed routing contract match. They share one committed loopback SOCKS
frontend and one provider generation, while each Grok child receives a distinct
leader socket and session identity. A different model, route mode, home-host
snapshot, phone identity, helper release, timeout, port, or resource limit is
rejected before it can mutate the active route. Once the last lease exits, the
supervisor proves exact cleanup and releases the compatibility fence. Setup,
stop, install, rollback, and other mutating maintenance remain interlocked with
the active generation. An explicit `-m`/`--model` is atomically remembered in
the compatibility choice file (release qualification never changes it); with no
saved choice, the opt-in lane reads Grok's `[models].default` setting.

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
Fixed qualification records bind the exact generated user and broker gate
digests. A changed gate generator therefore cannot reuse stale load/fault
results even if runtime files produce the same release ID. Version 1 has no
supported reset for a completed qualification directory, so that same-ID state
fails closed rather than becoming freshly qualifiable. Keep the exact installer
bytes frozen for a reproducible live install, qualification, rollback, and
reinstall exercise; a future reset/migration workflow is required before
supporting changed-generator same-ID requalification.

## How failure is handled

The watchdog checks the active rung every 10s (cheap: `ssh -O check`, or the tun plus the proxy
pid), and every 6th cycle proves real egress with one HTTP GET — a tunnel can be up while the far
end blackholes. On failure it repairs the *same* rung twice, and only then demotes:

```
home PC dies  ->  rebuild (x2)  ->  still dead?  ->  iPhone
iPhone dies   ->  restart (x2)  ->  still dead?  ->  VPN Gate server #1
VPN #1 dies   ->  one grace cycle  ->  VPN Gate server #2  ->  #3 ...
```

The compatibility watchdog model-reprobes the iPhone rung during repair and
periodic deep checks. The opt-in v1 supervisor model-qualifies every candidate
at admission and repair, while its periodic watchdog checks exact process and
exit identity. Thus an opt-in phone whose egress changes is repaired and
requalified, but a model-catalog change behind an unchanged exit IP is not
proactively detected until traffic fails and triggers repair.

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
| `GROK_MULTI_SESSION` | *(unset)* | exact value `1` enables the same-contract multi-session supervisor; every other value uses compatibility mode |
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
| `GROK_BLOCKED_CC` | EU + X-banned | exit countries that cannot serve the gated models |
| `VPNGATE_COUNTRIES` | — | force an ordered country list, e.g. `"VN JP"` |

State kept in this directory: `.model.choice` (your model), `.model.seen` (the menu you were last
offered), `.baseline.models`, `.unlocked.models`, `.egress.state`. The iPhone's Tailscale identity
is deliberately outside the project tree at `~/.local/state/grok-proxy/iphone`; treat
`tailscaled.state` as a credential and do not publish it.

## Caveats

- Keep the chosen home PC **awake**. A sleeping PC is a dead rung; you will land on VPN Gate.
- Keep Tailscale active on the iPhone. iOS suspension, loss of coverage, Low Power Mode, roaming,
  or switching between Wi-Fi and cellular can interrupt or change its public egress. The watchdog
  repairs or demotes; it never treats peer-online status alone as proof that the model still works.
- Traffic is `socks5h`, so DNS resolves at the egress. There is no DNS leak on any rung.
- The shared TCP SOCKS endpoint is loopback-only but has no cross-UID peer
  authentication. Multi-session v1 therefore supports only a single-tenant
  host where every local account able to connect to loopback is trusted; another
  local UID could otherwise consume the route or its bounded stream capacity.
- VPN Gate servers are shared/datacenter IPs, and grok.com may bot-flag them even when the region
  is right — prefer the home-PC path. Their country labels are also approximate (a "VN" entry may
  exit in JP). Any non-EU exit unlocks grok-4.5, so do not rely on a *specific* country.
- Region gating is xAI's deliberate policy; this routes your own account's grok traffic through
  your own home connection. Skim xAI's ToS before relying on it.
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

The iPhone addition is verified with a mocked userspace `tailscaled` and LocalAPI: separate state
and socket arguments, exact exit-node selection, exact listener ownership, setup gating, ladder
placement, lock-FD isolation, wrong-node rejection, and fail-closed forced selection all pass.
VPN Gate metadata validation, proxy-environment clearing, compatibility locking,
and opt-in same-contract admission have dedicated regressions too.

**Not yet exercised against a real iPhone data plane:** advertising and admin approval of this
phone, the sidecar's live tailnet login, cellular public egress, locked-screen longevity, and a real
model list/invocation through the phone still require the one-time setup above. A mocked sidecar
proves the wrapper contract; it does not prove iOS availability or carrier behavior.

Because nothing is pinned to a model name, there is no longer anything to update when xAI ships a
new flagship — the first run through a working tunnel will simply report what it unlocked.
