#!/usr/bin/env bash
# setup-grok-proxy-arch.sh
# Run on the Arch Linux PC (duc-arch-pc). Enables the SSH server and authorizes
# the openclaw VM's key so the VM can open a SOCKS tunnel out through this PC
# over Tailscale (grok-proxy, Option A). Run as your normal user; it uses sudo.
set -euo pipefail

PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbJ9Q7hJ+Kj3nj0jDvmi4AHBTMuAaHieDJpalbf/ixp grokproxy-openclaw-vm'

# Key body (the base64 blob) — stable identity used to de-dup/upgrade the entry on re-run,
# independent of any leading options or trailing comment.
KEYBODY='AAAAC3NzaC1lZDI1NTE5AAAAILbJ9Q7hJ+Kj3nj0jDvmi4AHBTMuAaHieDJpalbf/ixp'

# Lock this key to forwarding-only (no shell, no PTY, no agent/X11) and only to the hosts
# grok actually dials: the grok API + auth endpoints and the two IP/geo probes the watchdog
# uses. The VM opens the tunnel with `ssh -D` and socks5h (remote DNS), so the home PC sees
# each destination hostname and permitopen matches by name. If grok later dials a new host
# and the tunnel fails with "administratively prohibited", delete the permitopen="..." parts
# below (keep restrict,port-forwarding,command) — that still blocks shell and only widens the
# destination allowlist.
KEYOPTS='restrict,port-forwarding,command="/bin/false",permitopen="cli-chat-proxy.grok.com:443",permitopen="auth.x.ai:443",permitopen="api.ipify.org:443",permitopen="ipinfo.io:443"'

[[ $EUID -eq 0 ]] && { echo "Run as your normal user (not root); it will sudo when needed."; exit 1; }

echo "== grok-proxy: Arch setup =="

echo "[1/4] Installing/enabling the SSH server ..."
command -v sshd >/dev/null 2>&1 || sudo pacman -S --needed --noconfirm openssh
sudo systemctl enable --now sshd

echo "[2/4] Authorizing the openclaw VM key (restricted: forwarding-only, no shell) ..."
AK="$HOME/.ssh/authorized_keys"
install -d -m 700 "$HOME/.ssh"
touch "$AK"; chmod 600 "$AK"
# Upgrade in place: drop any prior entry for this key body (a bare key from an older run or a
# previously restricted one), then append the hardened form. Write via a temp in the same dir
# and mv so authorized_keys is never left truncated (a partial write could lock out the relay).
akt="$(mktemp "$AK.XXXXXX")"
{ grep -vF "$KEYBODY" "$AK" || true; printf '%s %s\n' "$KEYOPTS" "$PUBKEY"; } > "$akt"
chmod 600 "$akt"; mv -f "$akt" "$AK"

echo "[3/4] Opening SSH to the tailnet, if a firewall is active ..."
if systemctl is-active --quiet firewalld; then
  sudo firewall-cmd --permanent --add-service=ssh && sudo firewall-cmd --reload
elif command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
  sudo ufw allow from 100.64.0.0/10 to any port 22 proto tcp
else
  echo "      (no active firewalld/ufw detected — nothing to change)"
fi

echo "[4/4] Done."
TSIP="$(tailscale ip -4 2>/dev/null | head -1 || true)"
echo
echo "  Put these in hosts.conf on the openclaw VM:"
echo "    arch   ${TSIP:-<run: tailscale ip -4>}   $USER   22"
echo
echo "  Pin this PC's SSH host key on the VM so egress.sh (StrictHostKeyChecking=yes)"
echo "  trusts it — add this line to the VM's known_hosts next to egress.sh:"
HK="/etc/ssh/ssh_host_ed25519_key.pub"
if [[ -r "$HK" ]]; then
  awk -v ip="${TSIP:-<arch-tailscale-ip>}" 'NR==1{print "    " ip " " $1 " " $2}' "$HK"
  echo "    fingerprint (verify out-of-band): $(ssh-keygen -lf "$HK" 2>/dev/null | awk '{print $2}')"
else
  echo "    (ed25519 host key $HK not found — run: sudo ssh-keygen -A)"
fi
echo
echo "  Tip: keep this PC awake while using grok — it must be on to relay."
