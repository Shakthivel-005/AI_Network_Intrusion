#!/usr/bin/env bash
# Developer mode: run straight from the cloned folder, no system install.
cd "$(dirname "${BASH_SOURCE[0]}")"
if [ ! -d .venv ]; then
  python3 -m venv .venv && .venv/bin/pip install --upgrade pip && .venv/bin/pip install -r requirements.txt
fi
export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
exec .venv/bin/streamlit run app.py --server.address 127.0.0.1 --server.port "${NIDS_PORT:-8501}" --server.maxUploadSize 2000
