#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ is required"'
if [ ! -x .venv/bin/python ]; then "$PYTHON" -m venv .venv; fi
if ! .venv/bin/python -c 'import fastapi, uvicorn, httpx, dotenv' >/dev/null 2>&1 || ! cmp -s requirements.lock .venv/installed-requirements.lock; then
  .venv/bin/python -m pip install -r requirements.lock
  cp requirements.lock .venv/installed-requirements.lock
fi
printf '\nAI SOC Analyst → http://127.0.0.1:8000\nPress Ctrl+C to stop.\n\n'
exec .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
