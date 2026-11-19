#!/usr/bin/env bash
# Dynamic, SHA-256-verified cross-platform installer & readiness check for Google OSV-Scanner.
# Resolves the latest official release dynamically (zero hardcoded version IDs) without hitting GitHub API rate limits.
#
# Usage:
#   bash install_osv.sh --check   # Read-only diagnostic check (allowed without prompt)
#   bash install_osv.sh           # Download, SHA-256 verify, and install latest osv-scanner (triggers PreToolUse consent)

set -euo pipefail

MODE="install"
if [ "${1:-}" = "--check" ]; then
  MODE="check"
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'USAGE'
Usage:
  bash install_osv.sh --check   Check osv-scanner, PATH, and Google Cloud project readiness (read-only)
  bash install_osv.sh           Dynamically resolve latest release, verify SHA256SUMS, and install osv-scanner
USAGE
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="${SCRIPT_DIR}"
while [ "${PLUGIN_ROOT}" != "/" ] && [ ! -f "${PLUGIN_ROOT}/plugin.json" ] && [ ! -f "${PLUGIN_ROOT}/.claude-plugin/plugin.json" ]; do
  PLUGIN_ROOT="$(dirname "${PLUGIN_ROOT}")"
done

OSV_GITHUB_REPO_URL="${OSV_GITHUB_REPO_URL:-https://github.com/google/osv-scanner}"
TARGET_DIR="${OSV_INSTALL_DIR:-${HOME}/.local/bin}"

resolve_latest_tag() {
  if [ -n "${OSV_TARGET_TAG:-}" ]; then
    printf '%s' "${OSV_TARGET_TAG}"
    return 0
  fi
  local eff_url=""
  eff_url="$(curl -m 5 -fsSLI -o /dev/null -w '%{url_effective}' "${OSV_GITHUB_REPO_URL}/releases/latest" 2>/dev/null || true)"
  if [[ "${eff_url}" =~ /releases/tag/(v[0-9]+\.[0-9]+\.[0-9]+[^/?#]*) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

find_installed_osv() {
  if command -v osv-scanner >/dev/null 2>&1; then
    command -v osv-scanner
    return 0
  fi
  for candidate in "${TARGET_DIR}/osv-scanner" "${HOME}/.local/bin/osv-scanner" "/usr/local/bin/osv-scanner"; do
    if [ -x "${candidate}" ]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

extract_semver() {
  "$1" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true
}

if [ "${MODE}" = "check" ]; then
  echo "========================================================================"
  echo " 🛡️  GCP Artifact Trust Plugin - Environment & Readiness Check"
  echo "========================================================================"

  INSTALLED_BIN="$(find_installed_osv || true)"
  LATEST_TAG="$(resolve_latest_tag || true)"
  LATEST_VER="${LATEST_TAG#v}"
  GCP_PROJ="${GOOGLE_CLOUD_PROJECT:-}"
  if [ -z "${GCP_PROJ}" ] && command -v gcloud >/dev/null 2>&1; then
    GCP_PROJ="$(gcloud config get-value project 2>/dev/null || true)"
  fi

  OSV_READY=false
  if [ -n "${INSTALLED_BIN}" ]; then
    CURR_VER="$(extract_semver "${INSTALLED_BIN}")"
    ON_PATH_NOTE=""
    if ! command -v osv-scanner >/dev/null 2>&1; then
      ON_PATH_NOTE=" (⚠️ add $(dirname "${INSTALLED_BIN}") to PATH)"
    else
      OSV_READY=true
    fi
    VER_NOTE="${CURR_VER:-unknown}"
    if [ -n "${LATEST_VER}" ] && [ "${CURR_VER}" = "${LATEST_VER}" ]; then
      VER_NOTE="${VER_NOTE} (Latest)"
    elif [ -n "${LATEST_VER}" ]; then
      VER_NOTE="${VER_NOTE} (Latest upstream: ${LATEST_VER})"
    fi
    echo "OSV-Scanner CLI                : ✔ Installed (${INSTALLED_BIN})${ON_PATH_NOTE}"
    echo "OSV-Scanner Version            : ${VER_NOTE}"
  else
    echo "OSV-Scanner CLI                : ❌ Missing"
    echo "Latest Official Release        : ${LATEST_TAG:-unknown}"
  fi

  GUARD_STATUS="⚠️ Hook script missing"
  if [ -x "${PLUGIN_ROOT}/scripts/pre_tool_guard.sh" ] && [ -f "${PLUGIN_ROOT}/hooks.json" ]; then
    GUARD_STATUS="✔ Active (lifecycle scripts & BinAuthz policy protected)"
  fi

  echo "Python 3 (deps.dev / OSV API)  : $(command -v python3 >/dev/null 2>&1 && echo '✔ Available' || echo '❌ Missing')"
  echo "Google Cloud Project           : ${GCP_PROJ:-⚠️ Not set}"
  echo "PreToolUse Guardrail           : ${GUARD_STATUS}"
  echo "========================================================================"

  if [ "${OSV_READY}" = true ]; then
    echo "✔ Environment is READY for dependency trust, SBOM, and SLSA workflows."
    exit 0
  else
    echo "⚠️ Action required: Ask user permission before running install_osv.sh to install osv-scanner."
    exit 1
  fi
fi

# --- Install Mode ---
for cmd in curl; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "❌ Error: '${cmd}' is required to download osv-scanner." >&2
    exit 1
  fi
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "${OS}" in
  linux)  OS_KEY="linux" ;;
  darwin) OS_KEY="darwin" ;;
  *) echo "❌ Unsupported OS '${OS}'. Use official package managers on Windows (winget/scoop)." >&2; exit 1 ;;
esac

case "${ARCH}" in
  x86_64|amd64)  ARCH_KEY="amd64" ;;
  aarch64|arm64) ARCH_KEY="arm64" ;;
  *) echo "❌ Unsupported architecture '${ARCH}'." >&2; exit 1 ;;
esac

ASSET_NAME="osv-scanner_${OS_KEY}_${ARCH_KEY}"
LATEST_TAG="$(resolve_latest_tag || true)"
if [ -z "${LATEST_TAG}" ]; then
  echo "❌ Error: Could not dynamically resolve latest osv-scanner release tag from ${OSV_GITHUB_REPO_URL}." >&2
  exit 1
fi
TARGET_VER="${LATEST_TAG#v}"

INSTALLED_BIN="$(find_installed_osv || true)"
if [ -n "${INSTALLED_BIN}" ] && [ "${OSV_FORCE:-false}" != "true" ]; then
  CURR_VER="$(extract_semver "${INSTALLED_BIN}")"
  if [ "${CURR_VER}" = "${TARGET_VER}" ]; then
    echo "✅ osv-scanner ${CURR_VER} is already up to date at ${INSTALLED_BIN}."
    exit 0
  fi
fi

mkdir -p "${TARGET_DIR}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

DOWNLOAD_BASE="${OSV_GITHUB_REPO_URL}/releases/download/${LATEST_TAG}"
echo "⬇️  Downloading SLSA3 prebuilt binary ${ASSET_NAME} (${LATEST_TAG}) and SHA256SUMS..."
curl -fsSL "${DOWNLOAD_BASE}/${ASSET_NAME}" -o "${TMP_DIR}/${ASSET_NAME}"
curl -fsSL "${DOWNLOAD_BASE}/osv-scanner_SHA256SUMS" -o "${TMP_DIR}/osv-scanner_SHA256SUMS"

EXPECTED_SHA="$(awk -v asset="${ASSET_NAME}" '$2 == asset { print $1 }' "${TMP_DIR}/osv-scanner_SHA256SUMS")"
if [ -z "${EXPECTED_SHA}" ]; then
  echo "❌ Error: Asset '${ASSET_NAME}' not found in osv-scanner_SHA256SUMS." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "${TMP_DIR}/${ASSET_NAME}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "${TMP_DIR}/${ASSET_NAME}" | awk '{print $1}')"
else
  echo "❌ Error: Neither sha256sum nor shasum is available to verify binary integrity." >&2
  exit 1
fi

if [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then
  echo "❌ CRITICAL: SHA-256 checksum mismatch for ${ASSET_NAME}!" >&2
  echo "   Expected: ${EXPECTED_SHA}" >&2
  echo "   Actual:   ${ACTUAL_SHA}" >&2
  exit 1
fi
echo "✅ Verified SHA-256 checksum (${ACTUAL_SHA})"

# Optional bonus: verify SLSA3 provenance if slsa-verifier is installed on the host
if command -v slsa-verifier >/dev/null 2>&1; then
  echo "🔐 slsa-verifier detected — verifying SLSA Level 3 provenance (multiple.intoto.jsonl)..."
  curl -fsSL "${DOWNLOAD_BASE}/multiple.intoto.jsonl" -o "${TMP_DIR}/multiple.intoto.jsonl"
  slsa-verifier verify-artifact "${TMP_DIR}/${ASSET_NAME}" \
    --provenance-path "${TMP_DIR}/multiple.intoto.jsonl" \
    --source-uri "github.com/google/osv-scanner" \
    --source-tag "${LATEST_TAG}"
fi

install -m 0755 "${TMP_DIR}/${ASSET_NAME}" "${TARGET_DIR}/osv-scanner"
echo "✅ Installed osv-scanner ${LATEST_TAG} to ${TARGET_DIR}/osv-scanner"
"${TARGET_DIR}/osv-scanner" --version | head -n 2
