#!/usr/bin/env bash
set -euo pipefail

required=(
  bash calibre-debug chromium curl dvisvgm ebook-convert ffmpeg ffprobe
  getscipapers gh git gpg jq latexmk node npm pandoc pdftotext python rclone tmux
)
for executable in "${required[@]}"; do
  command -v "$executable" >/dev/null \
    || { echo "sandbox contract: missing executable: $executable" >&2; exit 2; }
done

[[ "$(node --version)" == "v22.23.2" ]] \
  || { echo "sandbox contract: unexpected Node version" >&2; exit 2; }
python - <<'PY'
import importlib
import importlib.metadata

modules = (
    "ebooklib", "feedparser", "fitz", "googleapiclient", "modal", "pikepdf",
    "requests", "selenium", "shapely", "svgelements", "pyzotero",
)
for name in modules:
    importlib.import_module(name)
expected = {
    "getscipapers-hoanganhduc": "0.1.4",
    "modal": "1.5.3",
    "pikepdf": "8.5.1",
}
for package, version in expected.items():
    if importlib.metadata.version(package) != version:
        raise SystemExit(f"sandbox contract: {package} version mismatch")
print("sandbox Python contract: passed")
PY
python -m pip check >/dev/null
getscipapers --help >/dev/null
modal --version >/dev/null

if [[ "${1:-}" != "--build" ]]; then
  [[ "$(id -u)" != 0 ]] \
    || { echo "sandbox contract: runtime user must be non-root" >&2; exit 2; }
  [[ -d /workspace && -w /workspace ]] \
    || { echo "sandbox contract: /workspace is not writable" >&2; exit 2; }
fi
echo "OpenClaw sandbox contract: passed"
