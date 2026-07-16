#!/usr/bin/env bash
set -euo pipefail
unset CDPATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

exec python3 "${SCRIPT_DIR}/pohw-community-onboarding.py" "$@" --repo-root "${REPO_ROOT}"
