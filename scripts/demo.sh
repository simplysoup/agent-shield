#!/usr/bin/env bash
# Safe, offline demonstration. No API keys or paid model calls.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
uv run --extra dev pytest -q
uv run --extra dev agentshield demo
uv run --extra dev agentshield benchmark
