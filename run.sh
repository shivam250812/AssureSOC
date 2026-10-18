#!/usr/bin/env bash
# One-command launcher: creates the venv on first run, installs deps, starts the console.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  if command -v uv >/dev/null 2>&1; then uv venv --python 3.12 .venv; else python3 -m venv .venv; fi
fi
if command -v uv >/dev/null 2>&1; then
  uv pip install --python .venv/bin/python -q -r requirements.txt
else
  .venv/bin/pip install -q -r requirements.txt
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY not set — running with the offline analyst (all detection features work)."
fi
echo "TriageForge → http://127.0.0.1:${PORT:-8000}"
exec .venv/bin/uvicorn triageforge.server:app --host 127.0.0.1 --port "${PORT:-8000}"
