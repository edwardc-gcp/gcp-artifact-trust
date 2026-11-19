#!/usr/bin/env bash
# Lightweight Pre-Install Package Reputation & Malware Checker for gcp-artifact-trust.
# Queries Google Open Source Insights (deps.dev v3 API) and OSV.dev (v1 API) with zero API keys required.
#
# Usage:
#   bash pkg_trust_check.sh <npm|pypi> <pkg[@version]>...
#
# Environment overrides (optional):
#   PKG_TRUST_MIN_AGE_DAYS  Minimum publish age in days before flagging brand-new releases (default: 7)
#   DEPS_DEV_API_BASE       Override deps.dev base URL (default: https://api.deps.dev/v3)
#   OSV_API_BASE            Override OSV query URL (default: https://api.osv.dev/v1/query)

set -euo pipefail

if [ "$#" -lt 2 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'USAGE'
Usage: bash pkg_trust_check.sh <npm|pypi> <pkg[@version]>...

Checks each package before installation:
  1. Existence on Google deps.dev (blocks AI-hallucinated / slopsquatted names)
  2. Release age >= PKG_TRUST_MIN_AGE_DAYS (default: 7 days; blocks newly registered typosquats)
  3. OSV.dev malware advisories (MAL-*) and known CRITICAL/HIGH vulnerabilities
USAGE
  [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && exit 0 || exit 2
fi

ECOSYSTEM_RAW="$1"
shift

case "${ECOSYSTEM_RAW}" in
  npm|node|nodejs|pnpm|yarn)
    DEPS_SYS="npm"
    OSV_ECO="npm"
    ;;
  pypi|pip|uv|python)
    DEPS_SYS="pypi"
    OSV_ECO="PyPI"
    ;;
  *)
    echo "❌ Unsupported ecosystem '${ECOSYSTEM_RAW}'. Expected: npm or pypi." >&2
    exit 2
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "❌ python3 is required to evaluate deps.dev and OSV JSON responses." >&2
  exit 2
fi

export PKG_TRUST_MIN_AGE_DAYS="${PKG_TRUST_MIN_AGE_DAYS:-7}"
export DEPS_DEV_API_BASE="${DEPS_DEV_API_BASE:-https://api.deps.dev/v3}"
export OSV_API_BASE="${OSV_API_BASE:-https://api.osv.dev/v1/query}"

python3 - "${DEPS_SYS}" "${OSV_ECO}" "$@" <<'PY'
import datetime
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

deps_sys = sys.argv[1]
osv_eco = sys.argv[2]
specs = sys.argv[3:]

min_age_days = int(os.environ.get("PKG_TRUST_MIN_AGE_DAYS", "7"))
deps_base = os.environ["DEPS_DEV_API_BASE"].rstrip("/")
osv_url = os.environ["OSV_API_BASE"]


def parse_spec(raw: str):
    raw = raw.strip()
    if any(raw.startswith(p) for p in ("http://", "https://", "git+", "file:", "github:")):
        return None, None, f"Direct URL/tarball spec '{raw}' bypasses registry provenance."
    if deps_sys == "npm":
        if raw.startswith("@"):
            parts = raw[1:].split("@", 1)
            name = "@" + parts[0]
            ver = parts[1] if len(parts) > 1 else None
        else:
            parts = raw.split("@", 1)
            name = parts[0]
            ver = parts[1] if len(parts) > 1 else None
        if ver and re.match(r"^[~^>=<*]", ver):
            ver = re.sub(r"^[~^>=<]+", "", ver)
        return name, (ver or None), None
    else:
        m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?(?:==([A-Za-z0-9_.+-]+))?$", raw)
        if not m:
            # Strip range operators like >=1.0 if provided
            m2 = re.match(r"^([A-Za-z0-9_.-]+)", raw)
            return (m2.group(1), None, None) if m2 else (None, None, f"Invalid package spec '{raw}'.")
        return m.group(1), m.group(2), None


def http_get_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "gcp-artifact-trust/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None


def http_post_json(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "gcp-artifact-trust/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def cvss3_base_score(vector: str):
    if not vector.startswith("CVSS:3."):
        return None
    parts = {}
    for token in vector.split("/")[1:]:
        if ":" in token:
            k, v = token.split(":", 1)
            parts[k] = v
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    ui_map = {"N": 0.85, "R": 0.62}
    cia_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    scope = parts.get("S")
    if scope not in ("U", "C"):
        return None
    pr_map = {"N": 0.85, "L": 0.68 if scope == "C" else 0.62, "H": 0.50 if scope == "C" else 0.27}
    try:
        av = av_map[parts["AV"]]
        ac = ac_map[parts["AC"]]
        pr = pr_map[parts["PR"]]
        ui = ui_map[parts["UI"]]
        c = cia_map[parts["C"]]
        i = cia_map[parts["I"]]
        a = cia_map[parts["A"]]
    except KeyError:
        return None
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min(impact + exploitability, 10.0) if scope == "U" else min(1.08 * (impact + exploitability), 10.0)
    scaled = round(raw * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def classify_osv_severity(vuln: dict) -> str:
    """Returns 'CRITICAL', 'HIGH', 'LOW_MOD', or 'UNRATED' across GHSA, PYSEC, and CVE records."""
    labels = []
    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.strip():
        labels.append(db_sev.strip().upper())

    sev_entries = list(vuln.get("severity") or [])
    for aff in vuln.get("affected") or []:
        eco_sev = (aff.get("ecosystem_specific") or {}).get("severity")
        if isinstance(eco_sev, str) and eco_sev.strip():
            labels.append(eco_sev.strip().upper())
        aff_db_sev = (aff.get("database_specific") or {}).get("severity")
        if isinstance(aff_db_sev, str) and aff_db_sev.strip():
            labels.append(aff_db_sev.strip().upper())
        sev_entries.extend(aff.get("severity") or [])

    if "CRITICAL" in labels:
        return "CRITICAL"
    if "HIGH" in labels:
        return "HIGH"

    max_score = None
    for entry in sev_entries:
        score_str = str(entry.get("score") or "").strip()
        if score_str.startswith("CVSS:3."):
            sc = cvss3_base_score(score_str)
            if sc is not None:
                max_score = sc if max_score is None else max(max_score, sc)
        elif score_str.startswith("CVSS:4."):
            if "/VC:H" in score_str or "/VI:H" in score_str:
                return "HIGH"
        else:
            try:
                sc = float(score_str)
                max_score = sc if max_score is None else max(max_score, sc)
            except ValueError:
                pass

    if max_score is not None:
        if max_score >= 9.0:
            return "CRITICAL"
        if max_score >= 7.0:
            return "HIGH"
        return "LOW_MOD"

    if any(lbl in ("LOW", "MODERATE", "MEDIUM") for lbl in labels):
        return "LOW_MOD"
    return "UNRATED"


overall_failed = False
now = datetime.datetime.now(datetime.timezone.utc)

for raw_spec in specs:
    if raw_spec.startswith("-"):
        continue
    name, requested_ver, parse_err = parse_spec(raw_spec)
    if parse_err:
        print(f"[BLOCK] {raw_spec}: {parse_err}")
        overall_failed = True
        continue

    encoded_name = urllib.parse.quote(name, safe="")
    pkg_url = f"{deps_base}/systems/{deps_sys}/packages/{encoded_name}"
    try:
        status, pkg_data = http_get_json(pkg_url)
    except Exception as exc:
        print(f"[ERROR] {name}: Failed to reach deps.dev ({exc}).")
        sys.exit(2)

    if status == 404 or not pkg_data or not pkg_data.get("versions"):
        print(f"[BLOCK] {name}: Package NOT FOUND on Google deps.dev ({deps_sys}). High slopsquatting / hallucination risk!")
        overall_failed = True
        continue
    if status != 200:
        print(f"[ERROR] {name}: Unexpected HTTP {status} from deps.dev.")
        sys.exit(2)

    versions = pkg_data.get("versions", [])
    target = None
    if requested_ver and requested_ver != "latest":
        for v in versions:
            if v.get("versionKey", {}).get("version") == requested_ver:
                target = v
                break
        if not target:
            print(f"[BLOCK] {name}@{requested_ver}: Version not indexed on deps.dev (either non-existent or published minutes ago).")
            overall_failed = True
            continue
    else:
        for v in versions:
            if v.get("isDefault"):
                target = v
                break
        if not target:
            target = versions[-1]

    resolved_ver = target.get("versionKey", {}).get("version", "unknown")
    pub_str = target.get("publishedAt", "")
    age_note = "age unknown"
    if pub_str:
        pub_dt = datetime.datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
        age_days = (now - pub_dt).total_seconds() / 86400.0
        age_note = f"published {age_days:.1f}d ago"
        if age_days < min_age_days:
            print(
                f"[BLOCK] {name}@{resolved_ver}: Newly published ({age_days:.1f}d < {min_age_days}d cooldown). "
                "Verify maintainer provenance before overriding PKG_TRUST_MIN_AGE_DAYS."
            )
            overall_failed = True
            continue

    deprecated_warn = ""
    if target.get("isDeprecated"):
        reason = target.get("deprecatedReason") or "marked deprecated"
        deprecated_warn = f" [WARN: deprecated - {reason}]"

    # Query OSV.dev for MAL-* malware advisories and CRITICAL/HIGH CVEs
    try:
        osv_resp = http_post_json(osv_url, {"package": {"name": name, "ecosystem": osv_eco}, "version": resolved_ver})
    except Exception as exc:
        print(f"[ERROR] {name}@{resolved_ver}: Failed to query OSV.dev ({exc}).")
        sys.exit(2)

    vulns = osv_resp.get("vulns") or []
    malicious = []
    high_crit = []
    other_vulns = []

    for v in vulns:
        vid = v.get("id", "")
        aliases = v.get("aliases") or []
        if vid.startswith("MAL-") or any(a.startswith("MAL-") for a in aliases):
            malicious.append(vid)
            continue
        sev_class = classify_osv_severity(v)
        if sev_class in ("CRITICAL", "HIGH"):
            high_crit.append(f"{vid} ({sev_class})")
        elif sev_class == "UNRATED":
            high_crit.append(f"{vid} (UNRATED-TREAT-HIGH)")
        else:
            other_vulns.append(vid)

    if malicious:
        print(f"[BLOCK] {name}@{resolved_ver}: KNOWN MALWARE on OSV ({', '.join(malicious)})!")
        overall_failed = True
        continue

    if high_crit:
        print(f"[BLOCK] {name}@{resolved_ver}: Known HIGH/CRITICAL vulnerabilities on OSV: {', '.join(high_crit)}.")
        overall_failed = True
        continue

    vuln_note = f", {len(other_vulns)} low/moderate advisory(s)" if other_vulns else ", 0 OSV advisories"
    print(f"[PASS]  {name}@{resolved_ver} ({deps_sys}, {age_note}{vuln_note}){deprecated_warn}")

sys.exit(1 if overall_failed else 0)
PY
