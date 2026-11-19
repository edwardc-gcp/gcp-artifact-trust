#!/usr/bin/env bash
# Automated CI Validation Suite for gcp-artifact-trust plugin.
# Verifies hardcoded path prohibition, shell syntax, Agent Skills conformance,
# PreToolUse hook matrix (Antigravity + Claude Code + Codex + no-jq/no-python3 POSIX fallback),
# offline mock tests for pkg_trust_check.sh, manifest parity, and Markdown links.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "🔍 Running gcp-artifact-trust Plugin Validation Suite..."

# 0. Hardcoded User Path Prohibition Gate
if grep -rnE '(/Users/[a-zA-Z0-9._-]+|/home/[a-zA-Z0-9._-]+)' SKILL.md CLAUDE.md README.md hooks.json hooks/ rules/ scripts/ skills/ --exclude="validate_plugin.sh"; then
  echo "❌ Hardcoded personal path detected in repository files!"
  exit 1
fi
echo "✅ Zero hardcoded user paths in repository files"

# 1. Shell Script Syntax & Executable Bit Check
for sh_file in scripts/pre_tool_guard.sh skills/dependency-trust/scripts/pkg_trust_check.sh skills/dependency-trust/scripts/install_osv.sh scripts/validate_plugin.sh; do
  bash -n "${sh_file}"
  chmod +x "${sh_file}"
  echo "✅ Shell syntax & executable bit valid: ${sh_file}"
done

# 1b. Self-Contained Skills Check
if grep -rnE '\.gemini/config/plugins|\.claude/plugins|\.\./\.\./' skills/*/SKILL.md; then
  echo "❌ Skills must be self-contained and must not reference install-specific or parent paths!"
  exit 1
fi
echo "✅ Skills are self-contained (no install-specific or parent traversal paths)"

# 1c. Agent Skills Frontmatter Conformance (https://agentskills.io/specification)
python3 -c '
import glob, os, re, sys
for path in sorted(glob.glob("skills/*/SKILL.md")):
    text = open(path).read()
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        sys.exit(f"❌ {path}: missing YAML frontmatter")
    fields = dict(line.split(": ", 1) for line in m.group(1).splitlines() if ": " in line)
    name = fields.get("name", "")
    if name != os.path.basename(os.path.dirname(path)) or not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) or len(name) > 64:
        sys.exit(f"❌ {path}: name must match its directory and use lowercase letters, digits, and hyphens")
    if not 0 < len(fields.get("description", "")) <= 1024:
        sys.exit(f"❌ {path}: description must be 1-1024 characters")
    if len(fields.get("compatibility", "")) > 500:
        sys.exit(f"❌ {path}: compatibility must be at most 500 characters")
print("✅ Agent Skills frontmatter conformant (name, description, compatibility)")
'

# 2a. Antigravity PreToolUse Hook Matrix (Standard PATH + Minimal POSIX Fallback without jq/python3)
python3 -c '
import json, subprocess

def run_hook(cmd, minimal=False):
    payload = json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}})
    if minimal:
        out = subprocess.check_output(
            ["bash", "-c", "jq() { return 127; }; python3() { return 127; }; export -f jq python3; source scripts/pre_tool_guard.sh"],
            input=payload,
            text=True,
        )
    else:
        out = subprocess.check_output(["bash", "scripts/pre_tool_guard.sh"], input=payload, text=True)
    return json.loads(out)["decision"]

cases = [
    # Node.js package install guard
    ("npm install lodash", "deny"),
    ("npm i express", "deny"),
    ("npm ci", "deny"),
    ("pnpm add zod", "deny"),
    ("yarn add axios", "deny"),
    ("npm install --ignore-scripts lodash", "allow"),
    ("npm ci --ignore-scripts", "allow"),
    ("pnpm add --ignore-scripts zod", "allow"),
    ("npm ci --ignore-scripts && npm install evil-pkg", "deny"),
    ("npm --prefix services/support-receipt install express", "deny"),
    ("npm --prefix services/support-receipt install --ignore-scripts express", "allow"),
    ("pnpm -C services/support-receipt add express", "deny"),
    ("yarn --cwd services/support-receipt add express", "deny"),
    ("yarn", "deny"),
    ("yarn --ignore-scripts", "allow"),
    ("npx --yes @cyclonedx/cyclonedx-npm", "force_ask"),
    ("npm sbom --sbom-format=cyclonedx --package-lock-only", "allow"),
    ("bash -c \"npm install lodash\"", "deny"),
    ("npm test", "allow"),
    ("npm run build", "allow"),
    ("npm install --help", "allow"),
    ("npm install --foreground-scripts sharp", "force_ask"),
    ("npm ci --ignore-scripts=false", "force_ask"),
    # Python package install guard
    ("pip install requests", "deny"),
    ("pip3 install flask", "deny"),
    ("python3 -m pip install fastapi", "deny"),
    ("uv add pydantic", "deny"),
    ("uv pip install httpx", "deny"),
    ("pip install --only-binary=:all: requests", "allow"),
    ("pip install --only-binary \":all:\" requests", "allow"),
    ("uv add --no-build pydantic", "allow"),
    ("pip install -e .", "allow"),
    ("pip install --no-binary :all: cryptography", "force_ask"),
    # GCP Binary Authorization & Cloud Run guards
    ("gcloud run deploy juice-shop --image=img --no-binary-authorization", "force_ask"),
    ("gcloud --project my-proj run deploy s --image=i --no-binary-authorization", "force_ask"),
    ("gcloud run deploy s --image=i --binary-authorization=default --breakglass=urgent", "force_ask"),
    ("gcloud run services update juice-shop --binary-authorization=none", "force_ask"),
    ("gcloud run deploy juice-shop --image=img --binary-authorization=default", "allow"),
    ("gcloud container binauthz policy import /tmp/policy.yaml", "force_ask"),
    ("gcloud --project=my-proj container binauthz policy import /tmp/p.yaml", "force_ask"),
    ("gcloud container binauthz attestors create artifact-trust-attestor", "force_ask"),
    ("gcloud container binauthz attestors public-keys add --attestor=a", "force_ask"),
    ("gcloud container binauthz policy export", "allow"),
    # External binary installation guard
    ("bash skills/dependency-trust/scripts/install_osv.sh", "force_ask"),
    ("bash \"/opt/p/skills/dependency-trust/scripts/install_osv.sh\"", "force_ask"),
    ("bash \"/opt/p/skills/dependency-trust/scripts/install_osv.sh\" --check", "allow"),
    ("bash '/opt/p/skills/dependency-trust/scripts/install_osv.sh' --help", "allow"),
    ("bash skills/dependency-trust/scripts/install_osv.sh --check", "allow"),
    ("bash skills/dependency-trust/scripts/install_osv.sh --help", "allow"),
    ("brew install osv-scanner", "force_ask"),
    ("go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest", "force_ask"),
    ("osv-scanner scan source -r .", "allow"),
    # Quote & commit-message false-positive immunity
    ("git commit -m \"docs: explain npm install and --no-binary-authorization\"", "allow"),
    ("echo \"npm install evil; gcloud container binauthz policy import p.yaml\"", "allow"),
    ("ls -la", "allow"),
]

count = 0
for minimal in (False, True):
    for cmd, expected in cases:
        got = run_hook(cmd, minimal)
        assert got == expected, f"{cmd!r} (minimal={minimal}): expected {expected}, got {got}"
        count += 1
print(f"✅ Antigravity PreToolUse hook tests passed ({count}/{count} assertions across standard & no-Python/no-jq environments)")
'

# 2b. Claude Code & Codex Hook Contract
python3 -c '
import json, os, subprocess

def run(payload, minimal=False, extra_env=None):
    env = dict(os.environ)
    env.pop("PLUGIN_ROOT", None)
    env.update(extra_env or {})
    data = json.dumps(payload)
    if minimal:
        cmd = ["bash", "-c", "jq() { return 127; }; python3() { return 127; }; export -f jq python3; source scripts/pre_tool_guard.sh"]
    else:
        cmd = ["bash", "scripts/pre_tool_guard.sh"]
    out = subprocess.check_output(cmd, input=data, text=True, env=env).strip()
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "allow"

claude = lambda c: {"tool_name": "Bash", "tool_input": {"command": c}}
codex = lambda c: {"tool_name": "Bash", "tool_input": {"command": c}, "turn_id": "turn-1"}
count = 0
for minimal in (False, True):
    for build, consent in ((claude, "ask"), (codex, "deny")):
        assert run(build("npm install lodash"), minimal) == "deny"
        assert run(build("pip install requests"), minimal) == "deny"
        assert run(build("npm install --ignore-scripts lodash"), minimal) == "allow"
        assert run(build("gcloud container binauthz policy import p.yaml"), minimal) == consent
        assert run(build("gcloud run deploy app --image=x --no-binary-authorization"), minimal) == consent
        assert run(build("brew install osv-scanner"), minimal) == consent
        assert run(build("git commit -m \"chore: npm install docs\""), minimal) == "allow"
        assert run(build("ls -la"), minimal) == "allow"
        count += 8
    assert run(claude("brew install osv-scanner"), minimal, {"PLUGIN_ROOT": "/opt/p"}) == "deny"
    count += 1
print(f"✅ Claude Code / Codex hook contract tests passed ({count}/{count} assertions)")
'

# 3. Offline Mock API Tests for pkg_trust_check.sh (Zero External Network Required)
python3 -c '
import datetime, http.server, json, os, subprocess, threading

now = datetime.datetime.now(datetime.timezone.utc)
old_ts = (now - datetime.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
young_ts = (now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

DEPS_DB = {
    "/systems/npm/packages/safe-pkg": {
        "versions": [{"versionKey": {"version": "1.2.0"}, "publishedAt": old_ts, "isDefault": True}]
    },
    "/systems/npm/packages/%40scope%2Fsafe": {
        "versions": [{"versionKey": {"version": "2.0.0"}, "publishedAt": old_ts, "isDefault": True}]
    },
    "/systems/npm/packages/brand-new-pkg": {
        "versions": [{"versionKey": {"version": "0.0.1"}, "publishedAt": young_ts, "isDefault": True}]
    },
    "/systems/npm/packages/evil-pkg": {
        "versions": [{"versionKey": {"version": "1.0.0"}, "publishedAt": old_ts, "isDefault": True}]
    },
    "/systems/pypi/packages/vuln-lib": {
        "versions": [{"versionKey": {"version": "3.1.0"}, "publishedAt": old_ts, "isDefault": True}]
    },
    "/systems/pypi/packages/cvss-pysec-lib": {
        "versions": [{"versionKey": {"version": "1.0.0"}, "publishedAt": old_ts, "isDefault": True}]
    },
}

OSV_DB = {
    ("npm", "evil-pkg", "1.0.0"): {"vulns": [{"id": "MAL-2026-9999", "summary": "Malicious credential stealer"}]},
    ("PyPI", "vuln-lib", "3.1.0"): {"vulns": [{"id": "GHSA-0000-1111-2222", "database_specific": {"severity": "CRITICAL"}}]},
    ("PyPI", "cvss-pysec-lib", "1.0.0"): {"vulns": [{"id": "PYSEC-2026-42", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]},
}

class MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        if self.path in DEPS_DB:
            body = json.dumps(DEPS_DB[self.path]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(length).decode())
        key = (req["package"]["ecosystem"], req["package"]["name"], req["version"])
        body = json.dumps(OSV_DB.get(key, {})).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

srv = http.server.HTTPServer(("127.0.0.1", 0), MockHandler)
port = srv.server_address[1]
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()

env = dict(os.environ)
env["DEPS_DEV_API_BASE"] = f"http://127.0.0.1:{port}"
env["OSV_API_BASE"] = f"http://127.0.0.1:{port}/osv"
script = "skills/dependency-trust/scripts/pkg_trust_check.sh"

def check(args):
    p = subprocess.run(["bash", script, *args], env=env, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr

rc, out = check(["npm", "safe-pkg", "@scope/safe"])
assert rc == 0 and "[PASS]" in out, f"Expected pass, got {rc}: {out}"

rc, out = check(["npm", "hallucinated-ai-pkg"])
assert rc == 1 and "NOT FOUND" in out, f"Expected 404 block, got {rc}: {out}"

rc, out = check(["npm", "brand-new-pkg"])
assert rc == 1 and "Newly published" in out, f"Expected cooldown block, got {rc}: {out}"

rc, out = check(["npm", "evil-pkg"])
assert rc == 1 and "KNOWN MALWARE" in out, f"Expected MAL-* block, got {rc}: {out}"

rc, out = check(["pypi", "vuln-lib==3.1.0"])
assert rc == 1 and "CRITICAL" in out, f"Expected CRITICAL CVE block, got {rc}: {out}"

rc, out = check(["pypi", "cvss-pysec-lib==1.0.0"])
assert rc == 1 and "PYSEC-2026-42" in out and "CRITICAL" in out, f"Expected PYSEC CVSS v3 vector block, got {rc}: {out}"

rc, out = check(["npm", "https://evil.example.com/pkg.tgz"])
assert rc == 1 and "Direct URL/tarball" in out, f"Expected tarball URL block, got {rc}: {out}"

srv.shutdown()
print("✅ Offline mock tests for pkg_trust_check.sh passed (7/7 scenarios: clean, scoped, 404 slopsquat, <7d cooldown, MAL-* malware, CRITICAL GHSA CVE, PYSEC CVSS v3 vector, tarball URL)")
'

# 3b. Offline Mock Server Tests for install_osv.sh (Dynamic Tag + SHA-256 Verify + Tamper Rejection)
python3 -c '
import hashlib, http.server, os, platform, subprocess, tempfile, threading

os_key = "linux" if platform.system().lower() == "linux" else "darwin"
mach = platform.machine().lower()
arch_key = "arm64" if mach in ("aarch64", "arm64") else "amd64"
asset_name = f"osv-scanner_{os_key}_{arch_key}"
fake_bin = b"#!/bin/sh\necho \"osv-scanner version: 2.99.0\"\n"
good_sha = hashlib.sha256(fake_bin).hexdigest()
tamper_mode = {"corrupt": False}

class ReleaseHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_HEAD(self):
        if self.path == "/releases/latest":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/releases/tag/v2.99.0")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
    def do_GET(self):
        if self.path == "/releases/latest":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/releases/tag/v2.99.0")
            self.end_headers()
        elif self.path.startswith("/releases/tag/"):
            self.send_response(200)
            self.end_headers()
        elif self.path.endswith(f"/{asset_name}"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"TAMPERED" if tamper_mode["corrupt"] else fake_bin)
        elif self.path.endswith("/osv-scanner_SHA256SUMS"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"{good_sha}  {asset_name}\n".encode())
        else:
            self.send_response(404)
            self.end_headers()

srv = http.server.HTTPServer(("127.0.0.1", 0), ReleaseHandler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

with tempfile.TemporaryDirectory() as tmp:
    env = dict(os.environ)
    env["OSV_GITHUB_REPO_URL"] = f"http://127.0.0.1:{port}"
    env["OSV_INSTALL_DIR"] = tmp
    env["PATH"] = f"{tmp}:/usr/bin:/bin"
    script = "skills/dependency-trust/scripts/install_osv.sh"

    # 1. Read-only --check when missing -> exit 1
    p = subprocess.run(["bash", script, "--check"], env=env, capture_output=True, text=True)
    assert p.returncode == 1 and "v2.99.0" in p.stdout, f"Expected missing check with dynamic tag, got {p.returncode}: {p.stdout}"

    # 2. Tampered binary -> SHA-256 mismatch rejected (exit 1)
    tamper_mode["corrupt"] = True
    p = subprocess.run(["bash", script], env=env, capture_output=True, text=True)
    assert p.returncode != 0 and "SHA-256 checksum mismatch" in (p.stdout + p.stderr), f"Expected tamper rejection, got: {p.stdout} {p.stderr}"

    # 3. Valid binary -> SHA-256 verified & installed (exit 0)
    tamper_mode["corrupt"] = False
    p = subprocess.run(["bash", script], env=env, capture_output=True, text=True)
    assert p.returncode == 0 and "Verified SHA-256 checksum" in p.stdout, f"Expected clean install, got: {p.stdout} {p.stderr}"

    # 4. Read-only --check after install -> exit 0 & Latest
    p = subprocess.run(["bash", script, "--check"], env=env, capture_output=True, text=True)
    assert p.returncode == 0 and "(Latest)" in p.stdout, f"Expected ready check, got: {p.stdout}"

srv.shutdown()
print("✅ Offline mock tests for install_osv.sh passed (dynamic tag resolution, tamper rejection, SHA-256 install, --check readiness)")
'

# 4. JSON Manifests & hooks.json Consistency Check
python3 -c '
import json, sys

with open("hooks.json") as fh:
    hooks = json.load(fh)
    assert "artifact-trust-safety-guard" in hooks, "Missing artifact-trust-safety-guard in hooks.json"
print("✅ hooks.json valid (Antigravity)")

with open("hooks/hooks.json") as fh:
    groups = json.load(fh)["hooks"]["PreToolUse"]
assert any(
    g.get("matcher") == "Bash"
    and any("${CLAUDE_PLUGIN_ROOT}/scripts/pre_tool_guard.sh" in h.get("command", "") for h in g.get("hooks", []))
    for g in groups
), "hooks/hooks.json must run ${CLAUDE_PLUGIN_ROOT}/scripts/pre_tool_guard.sh for the Bash tool"
print("✅ hooks/hooks.json valid (Claude Code & Codex)")

with open("plugin.json") as fh:
    plugin_name = json.load(fh)["name"]
with open(".claude-plugin/marketplace.json") as fh:
    market = json.load(fh)
assert market.get("name") and market.get("owner", {}).get("name"), "Claude marketplace needs name and owner.name"
assert any(p.get("name") == plugin_name and p.get("source") == "./" for p in market.get("plugins", [])), "Claude marketplace must list this plugin with source ./"
print("✅ .claude-plugin/marketplace.json valid (Claude Code)")

with open(".agents/plugins/marketplace.json") as fh:
    market = json.load(fh)
for p in market.get("plugins", []):
    assert p["source"]["path"].startswith("./"), "Codex marketplace source.path must start with ./"
    assert p["policy"]["installation"] and p["policy"]["authentication"] and p["category"], "Codex marketplace entries need policy and category"
assert any(p.get("name") == plugin_name for p in market.get("plugins", [])), "Codex marketplace must list this plugin"
print("✅ .agents/plugins/marketplace.json valid (Codex)")

manifests = ["plugin.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json"]
versions = set()
for m in manifests:
    with open(m) as f:
        data = json.load(f)
        versions.add(data.get("version"))
        if "author" in data and (not isinstance(data["author"], dict) or not data["author"].get("name")):
            sys.exit(f"❌ Invalid author schema in {m}")
        ver = data.get("version")
        print(f"✅ Manifest OK: {m} (v{ver})")
if len(versions) != 1:
    sys.exit(f"❌ Version mismatch across manifests: {versions}")
'

# 5. Relative Markdown Link Integrity Check
python3 -c '
import os, re, sys

md_files = [
    "README.md",
    "SKILL.md",
    "CLAUDE.md",
    "rules/artifact-trust-safety.md",
    "skills/dependency-trust/SKILL.md",
    "skills/slsa-verified-deploy/SKILL.md",
    "skills/slsa-verified-deploy/references/binauthz_kms_recipe.md",
]
link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
for md in md_files:
    base_dir = os.path.dirname(os.path.abspath(md))
    with open(md) as f:
        content = f.read()
    for target in link_re.findall(content):
        if target.startswith(("http://", "https://", "#")):
            continue
        resolved = os.path.normpath(os.path.join(base_dir, target.split("#")[0]))
        if not os.path.exists(resolved):
            sys.exit(f"❌ Broken link in {md}: {target} -> {resolved}")
print("✅ All Markdown links verified (0 broken paths).")
'

echo "🎉 All gcp-artifact-trust validation checks passed!"
