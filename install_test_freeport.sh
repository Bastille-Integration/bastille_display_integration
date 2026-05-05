#!/usr/bin/env bash
set -euo pipefail

# Ensure dependencies for test_freeport.py are installed on Linux or macOS.
# Uses a local .venv to avoid conflicts with system/Homebrew Python.

REQUIRED_PYTHON_MINOR=8  # minimum Python 3.x
VENV_DIR="$(cd "$(dirname "$0")" && pwd)/.venv"

die() { echo "ERROR: $*" >&2; exit 1; }

# ── Python ────────────────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)
        major=$("$candidate" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo 0)
        if [[ "$major" -eq 3 && "$ver" -ge "$REQUIRED_PYTHON_MINOR" ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done
[[ -n "$PYTHON" ]] || die "Python 3.$REQUIRED_PYTHON_MINOR+ not found. Install it and re-run."
echo "Using $($PYTHON --version)"

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating virtual environment at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists at $VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ── PyYAML ────────────────────────────────────────────────────────────────────
if ! "$VENV_PYTHON" -c "import yaml" &>/dev/null; then
    echo "Installing PyYAML into venv..."
    "$VENV_PIP" install --quiet pyyaml
else
    echo "PyYAML already installed."
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "Verifying imports..."
"$VENV_PYTHON" - <<'EOF'
import argparse, time, yaml, ssl, socket, logging, sys
print("  All required modules OK")
EOF

echo ""
echo "Setup complete. Run the test with:"
echo "  $VENV_DIR/bin/python test_freeport.py -c test_freeport_config.yaml"
