#!/usr/bin/env python3
"""Optional secret-zip upload form for a running Codespace.

Without uploading, the Codespace is a degraded (no-secrets) interactive replica.
Uploading the encrypted zip + password completes the full secret-backed replica.

The zip is uploaded straight into THIS container, used to restore secrets, and then
scrubbed — it is never stored on GitHub. The form binds to 0.0.0.0:8099; Codespaces
forwards the port behind GitHub auth (keep it Private). The password decrypts the zip
and is passed to the finisher via env, never written to disk.
"""
import html
import os
import subprocess
import threading

try:
    from flask import Flask, request, redirect
except ImportError:
    raise SystemExit("flask not installed (the devcontainer bootstrap installs it)")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = "/tmp/finish.log"
UPLOAD = "/tmp/uploaded-secrets.zip"
app = Flask(__name__)

FORM = """<!doctype html><meta charset=utf-8>
<title>coding-system-rebuild — live replica</title>
<style>body{font-family:system-ui;max-width:640px;margin:3rem auto;padding:0 1rem}</style>
<h2>Complete the full live replica (optional)</h2>
<p>This Codespace is already a working <b>degraded</b> replica (no secrets) — you can test
skills and configs right now. Upload your encrypted secrets zip only if you want the
<b>full</b> secret-backed replica. The zip is scrubbed after use and never stored on GitHub.</p>
<form method=post action=/restore enctype=multipart/form-data>
  <p>Encrypted secrets zip:<br><input type=file name=zip required></p>
  <p>Zip password:<br><input type=password name=password required></p>
  <p><label><input type=checkbox name=start_gateway value=1>
     Also start the OpenClaw gateway (LIVE — connects to your real channels; may
     conflict with your primary instance)</label></p>
  <p><button type=submit>Upload &amp; complete setup</button></p>
</form>
<p><a href="/status">view setup log &rarr;</a></p>"""


@app.get("/")
def index():
    return FORM


@app.post("/restore")
def restore():
    f = request.files.get("zip")
    pw = request.form.get("password", "")
    if not f or not pw:
        return "missing zip or password", 400
    f.save(UPLOAD)
    os.chmod(UPLOAD, 0o600)
    env = dict(os.environ,
               SECRETS=UPLOAD,
               CSR_SECRETS_PASSWORD=pw,
               START_GATEWAY="1" if request.form.get("start_gateway") else "0")

    def run():
        try:
            with open(LOG, "w") as lg:
                subprocess.run(["bash", os.path.join(REPO, ".devcontainer", "finish-setup.sh")],
                               env=env, stdout=lg, stderr=subprocess.STDOUT, cwd=REPO)
        finally:
            # backstop: finish-setup's EXIT trap normally shreds the zip; ensure it is
            # gone even if the finisher failed to launch at all.
            if os.path.exists(UPLOAD):
                try:
                    subprocess.run(["shred", "-u", UPLOAD], check=False)
                except Exception:
                    pass
                if os.path.exists(UPLOAD):
                    os.remove(UPLOAD)

    with open(LOG, "w") as lg:
        lg.write("starting — this can take several minutes (image pulls, restore)...\n")
    threading.Thread(target=run, daemon=True).start()
    return redirect("/status")


@app.get("/status")
def status():
    log = open(LOG).read() if os.path.exists(LOG) else "(no run yet)"
    return ("<!doctype html><meta charset=utf-8><title>setup log</title>"
            "<meta http-equiv=refresh content=4>"
            "<h2>Setup log (auto-refreshing)</h2><pre>" + html.escape(log) +
            "</pre><p><a href=\"/\">&larr; back</a></p>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8099)
