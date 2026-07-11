#!/usr/bin/env bash
# setup-grok-proxy-arch.sh
# Run on the Arch Linux PC (duc-arch-pc). Enables the SSH server and authorizes
# the openclaw VM's key so the VM can open a SOCKS tunnel out through this PC
# over Tailscale (grok-proxy, Option A). Run as your normal user; it uses sudo.
set -euo pipefail

PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbJ9Q7hJ+Kj3nj0jDvmi4AHBTMuAaHieDJpalbf/ixp grokproxy-openclaw-vm'

[[ $EUID -eq 0 ]] && { echo "Run as your normal user (not root); it will sudo when needed."; exit 1; }

echo "== grok-proxy: Arch setup =="

echo "[1/4] Installing/enabling the SSH server ..."
command -v sshd >/dev/null 2>&1 || sudo pacman -S --needed --noconfirm openssh
sudo systemctl enable --now sshd

echo "[2/4] Authorizing the openclaw VM key ..."
install -d -m 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"
grep -qxF "$PUBKEY" "$HOME/.ssh/authorized_keys" || echo "$PUBKEY" >> "$HOME/.ssh/authorized_keys"

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
echo "  Tip: keep this PC awake while using grok — it must be on to relay."
