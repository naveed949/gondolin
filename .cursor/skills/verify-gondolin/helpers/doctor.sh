#!/usr/bin/env bash
# Read-only readiness check. Exits 1 when this run must not drive a VM.
set -euo pipefail

HELPERS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "$HELPERS_DIR/common.sh"

fail() {
  echo "status=refuse"
  echo "reason=$1"
  exit 1
}

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
IMAGE_STORE="$(verify_gondolin_image_store)"

if ! command -v node >/dev/null 2>&1; then
  fail "node missing"
fi
echo "node=$(node -v)"
echo "node_path=$(command -v node)"
if ! verify_gondolin_node_ok; then
  fail "node $(node -v) is older than 23.6.0 (host/package.json engines)"
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
  fail "missing $QEMU"
fi
echo "qemu=$QEMU"
echo "qemu_path=$(command -v "$QEMU")"
echo "host_arch=$ARCH"

if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  echo "accel=kvm"
else
  echo "accel=tcg"
fi

if [[ ! -f "$BIN" ]]; then
  fail "missing built CLI at $BIN"
fi
echo "gondolin_bin=$BIN"
version=$(node -p "require('$REPO/host/package.json').version")
echo "package_version=$version"

if [[ ! -d "$IMAGE_STORE" ]]; then
  fail "image cache missing at $IMAGE_STORE"
fi
echo "image_store=$IMAGE_STORE"
image_ls=$(node "$BIN" image ls)
printf '%s\n' "$image_ls" | sed 's/^/image_ls=/'
if ! printf '%s\n' "$image_ls" | grep -E "^alpine-base:latest[[:space:]].*${ARCH}=" >/dev/null; then
  fail "alpine-base:latest for $ARCH is not in the image cache"
fi
echo "image_ref=alpine-base:latest"
echo "image_arch=$ARCH"

sessions_real=$(node -e 'const fs=require("fs"); const path=require("path"); const p=process.argv[1]; try { console.log(fs.realpathSync(p)); } catch { console.log(path.resolve(p)); }' "$GONDOLIN_SESSIONS_DIR")
default_real=$(node -e 'const fs=require("fs"); const path=require("path"); const p=process.argv[1]; try { console.log(fs.realpathSync(p)); } catch { console.log(path.resolve(p)); }' "$DEFAULT_SESSIONS")
echo "sessions_dir=$sessions_real"
echo "shared_sessions_dir=$default_real"
if [[ "$sessions_real" == "$default_real" ]]; then
  fail "GONDOLIN_SESSIONS_DIR is the shared session registry"
fi

live=$(
  node --input-type=module -e '
import fs from "node:fs";
const dir = process.argv[1];
if (!fs.existsSync(dir)) process.exit(0);
for (const name of fs.readdirSync(dir)) {
  if (!name.endsWith(".json")) continue;
  let info;
  try {
    info = JSON.parse(fs.readFileSync(`${dir}/${name}`, "utf8"));
  } catch {
    continue;
  }
  if (!info.id || !Number.isInteger(info.pid) || !info.socketPath) continue;
  let pidAlive = false;
  try {
    process.kill(info.pid, 0);
    pidAlive = true;
  } catch {
    pidAlive = false;
  }
  if (pidAlive && fs.existsSync(info.socketPath)) {
    console.log(`${info.id} ${info.pid}`);
  }
}
' "$GONDOLIN_SESSIONS_DIR"
)
if [[ -n "$live" ]]; then
  echo "sessions_live<<EOF"
  printf '%s\n' "$live"
  echo "EOF"
  fail "live session already registered in GONDOLIN_SESSIONS_DIR"
fi
echo "sessions_live=0"
echo "checkpoint_dir=$GONDOLIN_CHECKPOINT_DIR"
echo "verify_root=$GONDOLIN_VERIFY_ROOT"
echo "verify_run_id=$GONDOLIN_VERIFY_RUN_ID"
echo "status=ready"
