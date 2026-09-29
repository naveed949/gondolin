#!/usr/bin/env bash
# Shared paths and checks for verify-gondolin helpers.
set -euo pipefail

verify_gondolin_helpers_dir() {
  (cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
}

verify_gondolin_repo_root() {
  local helpers
  helpers="$(verify_gondolin_helpers_dir)"
  (cd "$helpers/../../../.." && pwd)
}

verify_gondolin_require_env() {
  local name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      echo "missing $name" >&2
      exit 1
    fi
  done
}

verify_gondolin_node_ok() {
  node -e 'const [maj, min] = process.versions.node.split(".").map(Number); if (!(maj > 23 || (maj === 23 && min >= 6))) process.exit(1)'
}

verify_gondolin_host_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo x86_64 ;;
    aarch64 | arm64) echo aarch64 ;;
    *)
      echo "unsupported host arch: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

verify_gondolin_qemu_bin() {
  case "$(verify_gondolin_host_arch)" in
    x86_64) echo qemu-system-x86_64 ;;
    aarch64) echo qemu-system-aarch64 ;;
  esac
}

verify_gondolin_default_sessions_dir() {
  local cache
  cache="${XDG_CACHE_HOME:-$HOME/.cache}"
  echo "$cache/gondolin/sessions"
}

verify_gondolin_image_store() {
  if [[ -n "${GONDOLIN_IMAGE_STORE:-}" ]]; then
    echo "$GONDOLIN_IMAGE_STORE"
    return
  fi
  local cache
  cache="${XDG_CACHE_HOME:-$HOME/.cache}"
  echo "$cache/gondolin/images"
}

verify_gondolin_bin() {
  echo "$(verify_gondolin_repo_root)/host/dist/bin/gondolin.js"
}

verify_gondolin_evidence_root() {
  echo "$(verify_gondolin_repo_root)/.cursor/skills/verify-gondolin/artifacts"
}
