#!/usr/bin/env bash
# Drive cli-exec once and write proof under artifacts/cli-exec/<run-id>/.
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
EVIDENCE="$(verify_gondolin_evidence_root)/cli-exec/$GONDOLIN_VERIFY_RUN_ID"
WORK="$GONDOLIN_VERIFY_ROOT/workspace"
MARKER="gondolin-verify-$GONDOLIN_VERIFY_RUN_ID"
PIDS="$GONDOLIN_VERIFY_ROOT/pids"

mkdir -p "$EVIDENCE" "$WORK" "$PIDS" "$GONDOLIN_SESSIONS_DIR" "$GONDOLIN_CHECKPOINT_DIR"
rm -f "$WORK/marker.txt"

export GONDOLIN_VMM=qemu
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  export GONDOLIN_START_TIMEOUT_MS="${GONDOLIN_START_TIMEOUT_MS:-300000}"
fi

CMD=(
  node "$BIN" exec
  --vmm qemu
  --mount-hostfs "$WORK:/workspace"
  --env "VERIFY_MARKER=$MARKER"
  -- /bin/sh -lc 'printf "%s\n" "$VERIFY_MARKER" > /workspace/marker.txt && uname -s && cat /etc/os-release'
)

{
  printf '%q ' "${CMD[@]}"
  printf '\n'
} >"$EVIDENCE/command.txt"

echo "cli-exec" >"$EVIDENCE/feature-id.txt"
echo "gondolin exec --mount-hostfs" >"$EVIDENCE/entry-point.txt"
echo "$MARKER" >"$EVIDENCE/marker-expected.txt"

{
  echo "verify_run_id=$GONDOLIN_VERIFY_RUN_ID"
  echo "sessions_dir=$GONDOLIN_SESSIONS_DIR"
  echo "checkpoint_dir=$GONDOLIN_CHECKPOINT_DIR"
  echo "workspace=$WORK"
  echo "node=$(node -v)"
  echo "node_path=$(command -v node)"
  echo "host_arch=$(verify_gondolin_host_arch)"
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    echo "accel=kvm"
  else
    echo "accel=tcg"
  fi
  echo "start_timeout_ms=${GONDOLIN_START_TIMEOUT_MS:-120000}"
  echo "qemu=$(verify_gondolin_qemu_bin)"
} >"$EVIDENCE/meta.txt"

record_descendants() {
  local root="$1"
  local out="$2"
  node --input-type=module -e '
import fs from "node:fs";
const root = Number(process.argv[1]);
const seen = new Set();
const stack = [root];
while (stack.length) {
  const pid = stack.pop();
  if (!Number.isInteger(pid) || pid <= 0 || seen.has(pid)) continue;
  seen.add(pid);
  const childrenPath = `/proc/${pid}/task/${pid}/children`;
  if (!fs.existsSync(childrenPath)) continue;
  const raw = fs.readFileSync(childrenPath, "utf8").trim();
  if (!raw) continue;
  for (const part of raw.split(/\s+/)) {
    const child = Number(part);
    if (Number.isInteger(child) && child > 0) stack.push(child);
  }
}
process.stdout.write([...seen].join("\n") + "\n");
' "$root" >>"$out"
}

set +e
"${CMD[@]}" >"$EVIDENCE/stdout.txt" 2>"$EVIDENCE/stderr.txt" &
drive_pid=$!
set -e
echo "$drive_pid" >"$PIDS/gondolin.pid"

(
  while kill -0 "$drive_pid" 2>/dev/null; do
    record_descendants "$drive_pid" "$PIDS/descendants" || true
    sleep 1
  done
) &
watcher_pid=$!

set +e
wait "$drive_pid"
status=$?
set -e
echo "$status" >"$EVIDENCE/exit-code.txt"
wait "$watcher_pid" 2>/dev/null || true
sort -u "$PIDS/descendants" -o "$PIDS/descendants" 2>/dev/null || true

set +e
node "$BIN" list >"$EVIDENCE/list-after.txt" 2>"$EVIDENCE/list-after.stderr.txt"
list_status=$?
set -e
echo "$list_status" >"$EVIDENCE/list-after.exit-code.txt"

if [[ -f "$WORK/marker.txt" ]]; then
  cp "$WORK/marker.txt" "$EVIDENCE/marker-host.txt"
else
  : >"$EVIDENCE/marker-host.txt"
fi

result=ok
if [[ "$status" -ne 0 ]]; then
  result=exec-exit
fi
if ! grep -q '^Linux$' "$EVIDENCE/stdout.txt"; then
  result=stdout-uname
fi
if ! grep -q 'Alpine Linux' "$EVIDENCE/stdout.txt"; then
  result=stdout-os-release
fi
got=$(cat "$EVIDENCE/marker-host.txt" 2>/dev/null || true)
if [[ "$got" != "$MARKER" ]]; then
  result=marker
fi
if ! grep -q '^No running sessions\.$' "$EVIDENCE/list-after.txt"; then
  result=session-left-running
fi
echo "$result" >"$EVIDENCE/result.txt"
echo "evidence=$EVIDENCE"
echo "result=$result"

if [[ "$result" != ok ]]; then
  exit 1
fi
