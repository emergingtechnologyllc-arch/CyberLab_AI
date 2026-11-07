#!/usr/bin/env bash
# Compatibility launcher. All features now live in one application.
set -euo pipefail
exec bash "$(dirname "$(readlink -f "$0")")/start.sh" "$@"
