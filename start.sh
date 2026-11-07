#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$(readlink -f "$0")")"
export CYBERLAB_MODEL="${CYBERLAB_MODEL:-llama3.2:latest}"
export CYBERLAB_V4_PORT="${CYBERLAB_V4_PORT:-8780}"
if [ -x .venv/bin/python ]; then
    exec .venv/bin/python -m cyberlab.server
fi
exec python3 -m cyberlab.server
