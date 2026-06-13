# Live replica in a GitHub Codespace

A `.devcontainer/` config turns this repo into a **live, interactive replica** you can
run in a GitHub Codespace — for live testing and demos. Two modes:

| Mode | You do | Result |
|---|---|---|
| **Degraded** (default) | nothing extra | Same no-secrets replica as the `install-degraded` CI job, but **interactive** — poke at skills/configs live. |
| **Full** (optional) | upload your encrypted zip via the form | Full secret-backed replica: real provider keys, skills, and (optionally) a live OpenClaw gateway. |

The secrets zip is **never stored on GitHub**. You upload it straight into the running
container; it is used to restore secrets and then scrubbed.

## Launch

1. On GitHub: **Code → Codespaces → Create codespace on `main`** (use **…** to pick a
   larger machine for the full replica — see *Resources* below).
2. Create-time runs `.devcontainer/bootstrap.sh`: installs the software stack, clones the
   (public) components, renders all configs, rebuilds Python envs, and runs a degraded
   verify. This takes a while the first time.
3. When it's up you already have a working degraded replica:
   ```bash
   make verify          # degraded health checks
   make test            # roundtrip + leak/canary/field-set guards + rotation units
   bash ~/.claude/skills/_run.sh skills/zotero/run_zot.sh doctor
   ```

## Optional: complete the full replica (upload the zip)

The Codespace forwards port **8099** ("Secret upload form"). Open it (it auto-previews),
then:
1. Choose your `coding-system-secrets-*.zip` and enter its password.
2. (Optional) tick *start the OpenClaw gateway* — see the warning below.
3. Submit. The form runs `.devcontainer/finish-setup.sh`, which restores secrets, pulls
   the docker images, completes the OpenClaw slice + skills, and rebuilds Python envs.
   Watch progress at **/status**; the zip is scrubbed when done.

After that, live-test with real credentials: `make verify`, `make verify-secret SECRET=…`,
zotero/digest/sage skills, etc.

## Important caveats (be honest about "exact")

- **Architecture:** Codespaces are **amd64**; the source system is **arm64**. This is a
  *functional* replica (configs, skills, settings, software, multi-arch images), not
  bit-identical. SageMath uses the **official amd64 image** here (arch-aware);
  `openclaw-sandbox` is multi-arch so it runs on amd64. arm64-only local binaries
  (e.g. `agy`) are reinstalled per-arch or unavailable.
- **Starting the gateway is LIVE:** it connects to your real channels (Telegram, Zulip,
  WhatsApp, …) with the **same bot tokens** as your primary instance and can conflict
  with it (e.g. Telegram `getUpdates` conflicts). Leave it off unless you intend a live
  channel demo, and stop your primary instance first if needed. It is **off by default**.
- **Resources:** the full replica pulls multi-GB images (`openclaw-sandbox` ~8.5GB,
  `sagemath` ~? , translation-server ~2GB) plus the toolchain. Pick a larger Codespaces
  machine (more storage) for the full path; the degraded mode fits the default.
  `texlive-full` and the docker images are **deferred** at create time to keep it fast
  (images pulled during the upload-finish step; install texlive manually if you need
  LaTeX skills: `bash bin/prepare.sh` with `SKIP_*` toggled).

## Security

- Port 8099 is forwarded behind GitHub auth — keep its visibility **Private**.
- The password is used to decrypt the zip and passed to the finisher via env only — not
  written to disk. The uploaded zip is `shred`ed after use.
- Nothing secret is committed or sent to GitHub; the Codespace filesystem is ephemeral
  and disappears when the Codespace is deleted.
