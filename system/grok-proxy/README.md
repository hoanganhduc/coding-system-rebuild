# grok-proxy — run grok from this VM through your home region (Option A)

grok.com gates models like **grok-4.5** by the region of the requesting IP. This
Oracle VM is in a blocked region; your home machines are not. These scripts route
**only the grok CLI** out through one of your home Tailscale machines (or, as a
fallback, a Vietnamese VPN Gate server), leaving everything else on the VM alone.

```
  this VM (openclaw) ──ssh -D SOCKS──▶ home PC ──▶ grok.com  (sees home region)
                    100.75.12.72        Windows / Arch
```

## Files

| File | Runs on | Purpose |
|------|---------|---------|
| `grok-remote` | this VM | wrapper: opens the tunnel, launches grok through it |
| `hosts.conf` | this VM | list of home egress PCs (fill in the usernames) |
| `vpngate-connect.sh` | this VM | fallback: VN VPN Gate egress, isolated in a netns |
| `id_grokproxy[.pub]` | this VM | dedicated SSH key (public key is baked into the setup scripts) |
| `dist/setup-grok-proxy-windows.bat` | Windows PC | enable OpenSSH server + authorize this VM's key |
| `dist/setup-grok-proxy-arch.sh` | Arch PC | enable sshd + authorize this VM's key |

## One-time setup

**1. On each home PC**, run its setup script:

- Windows (`desktop-bff6hdq`): copy `dist/setup-grok-proxy-windows.bat` over and
  double-click it (it self-elevates to Administrator).
- Arch (`duc-arch-pc`): copy `dist/setup-grok-proxy-arch.sh` over and run
  `bash setup-grok-proxy-arch.sh`.

Each script prints a ready-made `hosts.conf` line, e.g. `windows  100.123.194.47  YourUser  22`.

**2. On this VM**, put the printed username(s) into `~/grok-proxy/hosts.conf`
(replace the `CHANGE_ME` placeholders).

## Daily use

```bash
cd ~/grok-proxy
./grok-remote                 # opens tunnel via first reachable PC, launches grok
./grok-remote status          # show which PC is used + the public IP grok sees
./grok-remote ip              # just print that egress IP
./grok-remote --host arch     # force a specific PC
./grok-remote stop            # close the tunnel
```

If `grok models` / `grok-4.5` still doesn't appear, check `./grok-remote ip` —
it must show your **home** public IP, not the VM's.

## Fallback: VPN Gate (only when no home PC is awake)

```bash
./grok-remote --vpn           # tries VN, then JP/KR/TH/ID/… servers; first that connects wins
# or manage it directly:
sudo ./vpngate-connect.sh up|status|down
# force / tune the country order:
sudo VPNGATE_COUNTRIES="VN JP" ./vpngate-connect.sh up
```

It tries the preferred countries in order (VN first — the home region — then any
other country VPN Gate offers), skips servers it cannot reach, and fails over until
a tunnel comes up. Countries where **grok-4.5 is not available** are never used: the
whole EU (EU AI Act) — including VPN Gate's Romania server — and the countries where
X itself is banned (see `GROK_BLOCKED_CC` in `vpngate-connect.sh`). grok-4.5 is
offered in ~47 countries, so any non-EU exit unlocks it.

The VPN runs inside a network namespace (`grokvpn`), so only grok goes through it;
Tailscale, the OpenClaw gateway, and your SSH session keep their normal route.
Needs `openvpn` (the script installs it) and `sudo`. This is best-effort: VPN Gate
IPs are shared/datacenter addresses and grok.com may still bot-flag them even when
the region is right — prefer the home-PC path. Note VPN Gate's country labels are
approximate (a "VN" entry may actually exit in JP); for grok-4.5 any non-EU exit is
fine, but do not rely on it for a *specific* country.

## Notes / caveats

- Keep the chosen home PC **awake** while using grok (disable sleep).
- Traffic is `socks5h` (DNS resolved at the home PC) so there is no DNS leak.
- Region gating is xAI's deliberate policy; this routes your own account's grok
  traffic through your own home connection. Skim xAI's ToS before relying on it.
- **Not yet tested end-to-end**: the tunnel can't be verified until a home PC has
  its setup script run (Windows SSH port is currently closed, Arch is offline).
  The wrapper logic, host selection, and VPN Gate config selection are verified.
