#!/usr/bin/env bash
# Build the local Gondolin CLI and cache alpine-base:latest for this host arch.
set -euo pipefail

HELPERS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "$HELPERS_DIR/common.sh"

verify_gondolin_require_env \
  GONDOLIN_VERIFY_RUN_ID \
  GONDOLIN_VERIFY_ROOT \
  GONDOLIN_SESSIONS_DIR \
  GONDOLIN_CHECKPOINT_DIR

REPO="$(verify_gondolin_repo_root)"
BIN="$(verify_gondolin_bin)"
QEMU="$(verify_gondolin_qemu_bin)"
ARCH="$(verify_gondolin_host_arch)"
DEFAULT_SESSIONS="$(verify_gondolin_default_sessions_dir)"

if ! verify_gondolin_node_ok; then
  echo "node $(node -v 2>/dev/null || echo missing) at $(command -v node || echo missing) is older than 23.6.0" >&2
  echo "host/package.json engines requires node >=23.6.0. Put that node first on PATH and re-run." >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is missing. With the Node >=23.6 install: corepack enable && corepack prepare pnpm@8.15.0 --activate" >&2
  exit 1
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
  echo "missing $QEMU on PATH (host arch $ARCH)" >&2
  exit 1
fi

sessions_real=$(node -e 'const fs=require("fs"); const path=require("path"); const p=process.argv[1]; try { console.log(fs.realpathSync(p)); } catch { console.log(path.resolve(p)); }' "$GONDOLIN_SESSIONS_DIR")
default_real=$(node -e 'const fs=require("fs"); const path=require("path"); const p=process.argv[1]; try { console.log(fs.realpathSync(p)); } catch { console.log(path.resolve(p)); }' "$DEFAULT_SESSIONS")
if [[ "$sessions_real" == "$default_real" ]]; then
  echo "refuse: GONDOLIN_SESSIONS_DIR is the shared registry $DEFAULT_SESSIONS" >&2
  exit 1
fi

case "$GONDOLIN_VERIFY_ROOT" in
  /tmp/gondolin-verify-*) ;;
  *)
    echo "refuse: GONDOLIN_VERIFY_ROOT must be /tmp/gondolin-verify-<run-id>" >&2
    exit 1
    ;;
esac

mkdir -p \
  "$GONDOLIN_VERIFY_ROOT/workspace" \
  "$GONDOLIN_VERIFY_ROOT/pids" \
  "$GONDOLIN_SESSIONS_DIR" \
  "$GONDOLIN_CHECKPOINT_DIR"

cd "$REPO"
pnpm install
pnpm --filter @earendil-works/gondolin build

export GONDOLIN_VMM=qemu
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  echo "accel=kvm"
else
  export GONDOLIN_START_TIMEOUT_MS="${GONDOLIN_START_TIMEOUT_MS:-300000}"
  echo "accel=tcg"
  echo "GONDOLIN_START_TIMEOUT_MS=$GONDOLIN_START_TIMEOUT_MS"
fi

node "$BIN" help >/dev/null
echo "ready: gondolin help"

node "$BIN" image pull alpine-base:latest
echo "ready: image alpine-base:latest arch=$ARCH"
echo "gondolin_bin=$BIN"
echo "verify_root=$GONDOLIN_VERIFY_ROOT"
