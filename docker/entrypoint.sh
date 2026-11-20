#!/usr/bin/env bash
set -euo pipefail

# Restrict default file creation mask (owner rwx, group rx, world none)
umask 0027

DATA_DIR="${DATA_DIR:-/data}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${DATA_DIR}/artifacts}"
CODEX_HOME_DIR="${CODEX_HOME:-${DATA_DIR}/codex}"
WORKSPACES_DIR="${WORKSPACES_DIR:-/workspaces}"

# Ensure gateway-private directories exist and are strictly locked to UID 1001
mkdir -p "${DATA_DIR}" "${ARTIFACTS_DIR}" "${CODEX_HOME_DIR}"
chmod 0700 "${DATA_DIR}" "${ARTIFACTS_DIR}" "${CODEX_HOME_DIR}"

if [ ! -w "${DATA_DIR}" ] || [ ! -w "${ARTIFACTS_DIR}" ] || [ ! -w "${CODEX_HOME_DIR}" ]; then
  echo "ERROR: ${DATA_DIR}, ${ARTIFACTS_DIR}, and ${CODEX_HOME_DIR} must be writable by $(id -un) ($(id -u))" >&2
  exit 1
fi

# Verify shared worker workspace directory exists and is reachable
if [ ! -d "${WORKSPACES_DIR}" ]; then
  echo "WARNING: Expected directory ${WORKSPACES_DIR} does not exist; attempting to create it" >&2
  mkdir -p "${WORKSPACES_DIR}" || true
fi
if [ ! -r "${WORKSPACES_DIR}" ] || [ ! -x "${WORKSPACES_DIR}" ]; then
  echo "WARNING: Directory ${WORKSPACES_DIR} is not accessible to $(id -un) ($(id -u)); check volume ownership (expected UID 1002 / GID 1002)" >&2
fi

if [ "$#" -eq 0 ]; then
  exec node dist/index.js
fi

exec "$@"
