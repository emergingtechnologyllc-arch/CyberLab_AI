#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
export CYBERLAB_MODEL="${CYBERLAB_MODEL:-llama3.2:latest}"
export CYBERLAB_V4_PORT="${CYBERLAB_V4_PORT:-8780}"
exec python3 -m cyberlab.server
