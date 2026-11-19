#!/usr/bin/env bash
# Deterministic PreToolUse supply-chain guardrail for gcp-artifact-trust.
# Zero hard dependencies (pure bash + POSIX sed/grep/tr with optional jq/python3 acceleration).
# Compatible with Antigravity/Jetski (toolCall.args.CommandLine), Claude Code, and Codex (tool_input.command).

set -euo pipefail

RAW_INPUT="$(cat || true)"

# Detect payload format without forking so the fast path stays under 2ms.
RE_TOOL_INPUT='"tool_input"[[:space:]]*:'
RE_TURN_ID='"turn_id"[[:space:]]*:'
PAYLOAD_FORMAT="antigravity"
if [[ "${RAW_INPUT}" =~ ${RE_TOOL_INPUT} ]]; then
  PAYLOAD_FORMAT="claude"
  if [[ -n "${PLUGIN_ROOT:-}" || "${RAW_INPUT}" =~ ${RE_TURN_ID} ]]; then
    PAYLOAD_FORMAT="codex"
  fi
fi

emit_allow() {
  if [ "${PAYLOAD_FORMAT}" = "antigravity" ]; then
    printf '{"decision": "allow"}\n'
  fi
}

# Fast-path (<2ms): allow immediately if stdin doesn't mention any guarded tool or flag.
if [[ "${RAW_INPUT}" != *"npm"* \
   && "${RAW_INPUT}" != *"pnpm"* \
   && "${RAW_INPUT}" != *"yarn"* \
   && "${RAW_INPUT}" != *"pip"* \
   && "${RAW_INPUT}" != *"uv"* \
   && "${RAW_INPUT}" != *"npx"* \
   && "${RAW_INPUT}" != *"uvx"* \
   && "${RAW_INPUT}" != *"binauthz"* \
   && "${RAW_INPUT}" != *"binary-authorization"* \
   && "${RAW_INPUT}" != *"breakglass"* \
   && "${RAW_INPUT}" != *"install_osv.sh"* \
   && "${RAW_INPUT}" != *"osv-scanner"* ]]; then
  emit_allow
  exit 0
fi

extract_cmd() {
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "${RAW_INPUT}" | jq -r '.toolCall.args.CommandLine // .tool_input.command // empty' 2>/dev/null && return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "${RAW_INPUT}" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    c = (d.get("toolCall") or {}).get("args", {}).get("CommandLine") or (d.get("tool_input") or {}).get("command") or ""
    print(c, end="")
except Exception:
    pass
' 2>/dev/null && return 0
  fi
  printf '%s' "${RAW_INPUT}" | sed -nE 's/.*"CommandLine"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\1/p; s/.*"command"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\1/p' | head -n 1 | sed 's/\\"/"/g; s/\\\\/\\/g'
}

CMD="$(extract_cmd || true)"

if [ -z "${CMD}" ]; then
  emit_allow
  exit 0
fi

emit_response() {
  local decision="$1"
  local reason="$2"
  if [ "${PAYLOAD_FORMAT}" = "antigravity" ]; then
    printf '{"decision": "%s", "reason": "%s"}\n' "${decision}" "${reason}"
    return 0
  fi
  local permission="deny"
  if [[ "${decision}" == "force_ask" || "${decision}" == "ask" ]]; then
    if [ "${PAYLOAD_FORMAT}" = "codex" ]; then
      reason="${reason} Codex hooks cannot prompt for approval, so the command is blocked: show it to the user and let them run it themselves if they approve."
    else
      permission="ask"
    fi
  fi
  printf '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "%s", "permissionDecisionReason": "%s"}}\n' \
    "${permission}" "${reason}"
}

# Unwrap quoted script paths on `bash/sh "<script>.sh"` without splitting arguments, unwrap `bash -c "..."` / `eval "..."`
# into segments, preserve guarded flag values (`=":all:"`, `--prefix "..."`), neutralize remaining quoted literals, and split.
SEGMENTS="$(
  printf '%s\n' "${CMD}" | sed -E \
    -e 's/(^|[;&|[:space:](])(bash|sh)[[:space:]]+"([^";&|]*\.sh)"/\1\2 \3/g' \
    -e "s/(^|[;&|[:space:](])(bash|sh)[[:space:]]+'([^';&|]*\.sh)'/\1\2 \3/g" \
    -e 's/(^|[;&|[:space:](])((bash|sh|zsh|dash)([[:space:]]+-[a-zA-Z]+)*[[:space:]]+-[a-zA-Z]*c[a-zA-Z]*|eval)[[:space:]]+"(([^"\\]|\\.)*)"/\1; \5 ;/g' \
    -e "s/(^|[;&|[:space:](])((bash|sh|zsh|dash)([[:space:]]+-[a-zA-Z]+)*[[:space:]]+-[a-zA-Z]*c[a-zA-Z]*|eval)[[:space:]]+'([^']*)'/\1; \5 ;/g" \
    -e 's/="([^";&|]*)"/=\1/g' \
    -e "s/='([^';&|]*)'/=\1/g" \
    -e 's/(--only-binary|--binary-authorization|--prefix|--dir|--cwd|-C|--project)[[:space:]]+"([^";&|]*)"/\1=\2/g' \
    -e "s/(--only-binary|--binary-authorization|--prefix|--dir|--cwd|-C|--project)[[:space:]]+'([^';&|]*)'/\1=\2/g" \
    -e 's/"([^"\\]|\\.)*"/""/g' \
    -e "s/'[^']*'/''/g" \
  | tr ';&|()' '\n\n\n\n\n'
)"

PREFIX='^[[:space:]]*(([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*|env|sudo|nice|nohup|time|command|exec|timeout([[:space:]]+-[^[:space:]]+)*[[:space:]]+[0-9.]+[smhd]?)[[:space:]]+)*([^[:space:]]*/)?'
PKG_PRE='([[:space:]]+((--prefix|--dir|--cwd|-C)(=|[[:space:]]+)[^[:space:]]+|-[a-zA-Z0-9-]+(=[^[:space:]]+)?))*'
GCLOUD_PRE='([[:space:]]+((--project|--account|--impersonate-service-account|--billing-project|--configuration|--verbosity|--flags-file)(=|[[:space:]]+)[^[:space:]]+|--[a-zA-Z0-9-]+(=[^[:space:]]+)?|-[a-zA-Z]+|alpha|beta))*'
END='([[:space:]]|$)'

seg_matches() { printf '%s\n' "$1" | grep -qE "$2"; }
seg_is_readonly_flag() { seg_matches "$1" '[[:space:]](-h|--help|-v|--version|--dry-run)([[:space:]]|$)'; }

DENY_REASON=""
ASK_REASON=""

while IFS= read -r seg; do
  [ -z "${seg}" ] && continue

  # 1a. Node.js explicit lifecycle script execution (`--foreground-scripts` or `--ignore-scripts=false`) -> force_ask,
  #     or missing `--ignore-scripts` (including `--prefix`/`-C` flags and bare `yarn`) -> deny.
  if { seg_matches "${seg}" "${PREFIX}(npm${PKG_PRE}[[:space:]]+(i|install|add|ci)|pnpm${PKG_PRE}[[:space:]]+(i|install|add)|yarn${PKG_PRE}[[:space:]]+(install|add))${END}" \
       || seg_matches "${seg}" "${PREFIX}yarn${PKG_PRE}[[:space:]]*$"; } \
     && ! seg_is_readonly_flag "${seg}"; then
    if seg_matches "${seg}" '[[:space:]](--foreground-scripts|--ignore-scripts=(false|False|FALSE|0))([[:space:]]|$)'; then
      ASK_REASON="Node.js lifecycle script execution requested (--foreground-scripts / --ignore-scripts=false). Postinstall scripts can execute arbitrary code or hijack local AI CLIs. Explicit human confirmation is required."
      continue
    fi
    if ! seg_matches "${seg}" '[[:space:]]--ignore-scripts([[:space:]]|=true|$)'; then
      DENY_REASON="Blocked by gcp-artifact-trust: Node.js install/ci commands must include '--ignore-scripts' to prevent malicious postinstall execution. When adding new packages, run pkg_trust_check.sh npm <pkg> first, then install with '--ignore-scripts'."
      break
    fi
  fi

  # 1a-exec. Transient package execution (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `uvx`) -> force_ask
  if seg_matches "${seg}" "${PREFIX}(npx|npm${PKG_PRE}[[:space:]]+exec|pnpm${PKG_PRE}[[:space:]]+dlx|yarn${PKG_PRE}[[:space:]]+dlx|uvx)${END}" \
     && ! seg_is_readonly_flag "${seg}"; then
    if ! seg_matches "${seg}" '[[:space:]]--ignore-scripts([[:space:]]|=true|$)'; then
      ASK_REASON="Transient package execution detected (npx / npm exec / dlx / uvx), which downloads and executes packages outside lockfile controls. Explicit human confirmation is required."
    fi
  fi

  # 1b. Python package installation without binary-only guard (`--only-binary=:all:` or `uv add --no-build`) -> deny / force_ask
  if seg_matches "${seg}" "${PREFIX}(pip3?([[:space:]]+-[^[:space:]]+)*[[:space:]]+install|(python3?[[:space:]]+-m[[:space:]]+)?pip([[:space:]]+-[^[:space:]]+)*[[:space:]]+install|uv([[:space:]]+-[^[:space:]]+)*[[:space:]]+(add|pip[[:space:]]+install))${END}" \
     && ! seg_is_readonly_flag "${seg}"; then
    # Allow local editable installs (`pip install -e .`) when explicitly developing the local repo itself
    if seg_matches "${seg}" '[[:space:]](-e|--editable)[[:space:]]+\.([[:space:]]|$)'; then
      continue
    fi
    if seg_matches "${seg}" '[[:space:]]--no-binary([[:space:]]|=|$)'; then
      ASK_REASON="Python source build requested (--no-binary), which executes arbitrary setup.py / build hooks. Explicit human confirmation is required."
      continue
    fi
    if ! seg_matches "${seg}" '[[:space:]](--only-binary(=|[[:space:]]+):all:|--no-build)([[:space:]]|$)'; then
      DENY_REASON="Blocked by gcp-artifact-trust: Python installs must pass '--only-binary=:all:' (pip / uv pip) or '--no-build' (uv add) to prevent arbitrary setup.py execution. When adding new packages, run pkg_trust_check.sh pypi <pkg> first."
      break
    fi
  fi

  # 2a. Cloud Run Binary Authorization bypass or --breakglass -> force_ask
  if seg_matches "${seg}" "${PREFIX}gcloud${GCLOUD_PRE}[[:space:]]+run[[:space:]]+(deploy|services[[:space:]]+update)${END}" \
     && seg_matches "${seg}" '[[:space:]](--no-binary-authorization|--breakglass(=[^[:space:]]*)?|--binary-authorization(=|[[:space:]]+)(none|false|False|FALSE|0))([[:space:]]|$)'; then
    ASK_REASON="CRITICAL SECURITY WARNING: disabling Cloud Run Binary Authorization or using --breakglass bypasses SLSA provenance and KMS attestation enforcement. Explicit human confirmation is required."
  fi

  # 2b. GCP Binary Authorization policy, attestor, key, or IAM mutation -> force_ask
  if seg_matches "${seg}" "${PREFIX}gcloud${GCLOUD_PRE}[[:space:]]+container[[:space:]]+binauthz[[:space:]]+(policy[[:space:]]+(import|set-iam-policy)|attestors[[:space:]]+(create|delete|update|set-iam-policy|add-iam-policy-binding|remove-iam-policy-binding|public-keys[[:space:]]+(add|remove|update)))${END}" \
     && ! seg_is_readonly_flag "${seg}"; then
    ASK_REASON="Project-wide GCP Binary Authorization policy, attestor, key, or IAM mutation detected. Explicit human confirmation is required."
  fi

  # 2c. External osv-scanner binary installation (allow read-only `install_osv.sh --check` / `--help`) -> force_ask
  if seg_matches "${seg}" 'install_osv\.sh([[:space:]]|$)' \
     && ! seg_matches "${seg}" '[[:space:]](--check|-h|--help)([[:space:]]|$)'; then
    ASK_REASON="External binary installation or update detected (install_osv.sh). Explicit user permission is required before downloading or updating osv-scanner."
  fi
  if { seg_matches "${seg}" "${PREFIX}(go[[:space:]]+install|brew[[:space:]]+(install|upgrade)|apt(-get)?[[:space:]]+install|curl|wget)${END}" \
       && seg_matches "${seg}" 'osv-scanner'; } && ! seg_is_readonly_flag "${seg}"; then
    ASK_REASON="External binary installation or download detected (osv-scanner). Explicit user permission is required before installing tools."
  fi
done <<EOF
${SEGMENTS}
EOF

if [ -n "${DENY_REASON}" ]; then
  emit_response "deny" "${DENY_REASON}"
  exit 0
fi

if [ -n "${ASK_REASON}" ]; then
  emit_response "force_ask" "${ASK_REASON}"
  exit 0
fi

emit_allow
