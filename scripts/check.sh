#!/usr/bin/env bash
set -euo pipefail
REDOPS_PROJECT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REDOPS_PROJECT_ROOT"
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m build
