#!/usr/bin/env bash
set -euo pipefail

# Run this with a separately obtained, reviewed wakeio-security-ci source tree
# and a target checkout. The action runner performs its own dependency and
# pinned scanner setup from ACTION_DIR.
ACTION_DIR="${WAKEIO_ACTION_DIR:?set WAKEIO_ACTION_DIR to the action checkout}"
TARGET_DIR="${TARGET_DIR:-$PWD}"
OUT_DIR="${OUT_DIR:-wakeio-security-reports}"

export WAKEIO_ACTION_PATH="$ACTION_DIR"
export GITHUB_WORKSPACE="$TARGET_DIR"
export WAKEIO_SOURCE="${WAKEIO_SOURCE-.}"
export WAKEIO_URL="${WAKEIO_URL:-}"
export WAKEIO_OUT="$OUT_DIR"
export WAKEIO_TOOLS="${WAKEIO_TOOLS:-gitleaks,osv,trivy}"
export WAKEIO_FAIL_ON="${WAKEIO_FAIL_ON:-high}"
node "$ACTION_DIR/scripts/action-run.mjs"
