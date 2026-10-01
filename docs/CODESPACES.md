# Codespaces: degraded, no-secrets development replica

The devcontainer provides an interactive **degraded** replica for source tests,
configuration rendering, and no-secret skill checks. It deliberately does not
accept recovery media or claim to be a complete restored host.

Create a Codespace on `main`. Its `onCreateCommand` installs the lightweight
substrate and runs the degraded installer. Useful checks after startup are:

```bash
make test
bash bin/verify.sh --profile ci
python3 system/software/lockctl.py --arch amd64 validate
```

Codespaces are amd64 containers and do not reproduce a stock host's boot,
linger, full user-systemd lifecycle, Docker host policy, or production channel
ownership. Uploading an old password ZIP would also bypass the signed
recovery-set and 2-of-4 escrow contract. For those reasons the former secret
upload form was removed.

Use the normal bare-host path for a complete recovery:

```bash
/usr/bin/bash -p "$HOME/secrets-restore-inbox/restore-ubuntu.sh"
```

That path is limited to Ubuntu 24.04 on amd64 or arm64 and performs the full
software, credential, image, service, scheduler, MCP, and target verification
gates.
