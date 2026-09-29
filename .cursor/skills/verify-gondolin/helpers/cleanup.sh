#!/usr/bin/env bash
# Stop processes this run recorded, then delete the verify root. Artifacts stay.
set -euo pipefail

HELPERS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "$HELPERS_DIR/common.sh"

verify_gondolin_require_env GONDOLIN_VERIFY_ROOT GONDOLIN_SESSIONS_DIR

EVIDENCE="$(verify_gondolin_evidence_root)"
case "$GONDOLIN_VERIFY_ROOT" in
  /tmp/gondolin-verify-*) ;;
  *)
    echo "refuse: GONDOLIN_VERIFY_ROOT must be /tmp/gondolin-verify-<run-id>" >&2
    exit 1
    ;;
esac

if [[ "$GONDOLIN_VERIFY_ROOT" == "$EVIDENCE" || "$GONDOLIN_VERIFY_ROOT" == "$EVIDENCE"/* ]]; then
  echo "refuse: verify root overlaps evidence at $EVIDENCE" >&2
  exit 1
fi

kill_if_ours() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  [[ -r "/proc/$pid/cmdline" ]] || return 0
  local cmd
  cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline")
  case "$cmd" in
    *host/dist/bin/gondolin.js* | *qemu-system-*)
      echo "kill $pid $cmd"
      kill "$pid" 2>/dev/null || true
      ;;
    *)
      echo "skip $pid $cmd"
      ;;
  esac
}

collect_pids() {
  local file
  if [[ -d "$GONDOLIN_VERIFY_ROOT/pids" ]]; then
    for file in "$GONDOLIN_VERIFY_ROOT/pids"/*; do
      [[ -f "$file" ]] || continue
      cat "$file"
    done
  fi
  if [[ -d "$GONDOLIN_SESSIONS_DIR" ]]; then
    node --input-type=module -e '
import fs from "node:fs";
const dir = process.argv[1];
if (!fs.existsSync(dir)) process.exit(0);
for (const name of fs.readdirSync(dir)) {
  if (!name.endsWith(".json")) continue;
  try {
    const info = JSON.parse(fs.readFileSync(`${dir}/${name}`, "utf8"));
    if (Number.isInteger(info.pid)) console.log(info.pid);
  } catch {
    // ignore malformed metadata
  }
}
' "$GONDOLIN_SESSIONS_DIR"
  fi
}

mapfile -t pids < <(collect_pids | awk '/^[0-9]+$/ { print $1 }' | sort -u)
for pid in "${pids[@]}"; do
  kill_if_ours "$pid" || true
done
sleep 1
for pid in "${pids[@]}"; do
  if [[ -r "/proc/$pid/cmdline" ]]; then
    cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline")
    case "$cmd" in
      *host/dist/bin/gondolin.js* | *qemu-system-*)
        echo "kill -9 $pid"
        kill -9 "$pid" 2>/dev/null || true
        ;;
    esac
  fi
done

rm -rf "$GONDOLIN_VERIFY_ROOT"
echo "removed $GONDOLIN_VERIFY_ROOT"
echo "kept $EVIDENCE"
