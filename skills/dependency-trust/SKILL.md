---
name: dependency-trust
description: Pre-install package reputation checks (deps.dev + OSV malware guard), lifecycle-script-safe dependency installation, OSV lockfile vulnerability auditing/remediation, and CycloneDX SBOM generation.
compatibility: Requires python3 and internet access for deps.dev/OSV API queries; uses osv-scanner CLI for repository lockfile audits.
---

# Dependency Trust & OSV Supply-Chain Workflow

Use this skill whenever adding third-party dependencies, auditing lockfiles for CVEs or malware, remediating vulnerable packages, or generating an SBOM.

## 1. Pre-Install Reputation & Malware Gate (Mandatory Before Adding Packages)

AI coding assistants can hallucinate non-existent package names (*slopsquatting*) or pull newly published malicious versions. Before installing any new Node.js or Python package, query Google Open Source Insights (`deps.dev`) and `OSV.dev` using the bundled helper (replace `<skill-dir>` with the directory containing this `SKILL.md`):

```bash
# Check npm / pnpm / yarn packages
bash "<skill-dir>/scripts/pkg_trust_check.sh" npm <pkg1> <pkg2@version>

# Check PyPI (pip / uv) packages
bash "<skill-dir>/scripts/pkg_trust_check.sh" pypi <pkg1> <pkg2==version>
```

### Interpreting `pkg_trust_check.sh` Results
* **`[PASS]` (`exit 0`)**: Package exists on `deps.dev`, target version meets the publish cooldown (`>= 7` days by default), has zero `MAL-*` malware advisories, and zero `HIGH`/`CRITICAL` OSV advisories.
* **`[BLOCK]` (`exit 1`)**: Do **NOT** install the package. Report the exact reason to the user:
  * *NOT FOUND on deps.dev*: Likely an AI-hallucinated or slopsquatted name—verify the official package name.
  * *Newly published (`< 7d`)*: Potential typosquat or compromised maintainer release—choose a battle-tested release or ask the user before overriding `PKG_TRUST_MIN_AGE_DAYS`.
  * *KNOWN MALWARE (`MAL-*`) or `HIGH`/`CRITICAL` OSV advisory*: Select a patched version or an alternative library.

---

## 2. Lifecycle-Script-Safe Installation

Supply-chain attacks such as *s1ngularity* execute credential-stealing payloads and hijack local AI CLIs inside `postinstall` or `setup.py` hooks. Always disable install-time code execution (enforced by `pre_tool_guard.sh`):

```bash
# Node.js (npm / pnpm / yarn)
npm install --ignore-scripts <pkg>
npm ci --ignore-scripts
pnpm add --ignore-scripts <pkg>
yarn add --ignore-scripts <pkg>

# Python (pip / uv)
pip install --only-binary=:all: <pkg>
uv add --no-build <pkg>
uv pip install --only-binary=:all: <pkg>
```

If a native addon genuinely requires build scripts after passing `pkg_trust_check.sh`, explain why and ask the user before running with `--foreground-scripts` or `--no-binary`.

---

## 3. Repository Vulnerability Auditing & Guided Remediation (`osv-scanner`)

Use Google's open-source **`osv-scanner`** directly:

1. **Check environment readiness** (read-only check; if `osv-scanner` is missing or outdated, run `[scripts/install_osv.sh](scripts/install_osv.sh)` without `--check`, which dynamically resolves the latest SLSA3 GitHub Release, verifies `osv-scanner_SHA256SUMS`, and prompts the user via `pre_tool_guard.sh` before downloading):
   ```bash
   # Read-only readiness check
   bash "<skill-dir>/scripts/install_osv.sh" --check

   # Install or update latest SHA-256-verified release (requires user confirmation)
   bash "<skill-dir>/scripts/install_osv.sh"
   ```
2. **Audit lockfiles & separate production vs. dev risk**:
   ```bash
   # Full repository lockfile scan
   osv-scanner scan source -r .

   # Target a specific lockfile directly (helpful when a parent .gitignore ignores lockfiles)
   osv-scanner scan source -L package-lock.json
   osv-scanner scan source --no-ignore -r ./services/my-service

   # Export machine-readable JSON or SARIF when triaging large repos
   osv-scanner scan source -r . --format json --output-file .artifact-trust/osv-results.json
   ```
3. **Guided non-breaking remediation** (supported on `package.json` + `package-lock.json` and `pom.xml`):
   ```bash
   # Preview non-breaking upgrades while blocking lifecycle scripts
   NPM_CONFIG_IGNORE_SCRIPTS=true osv-scanner fix -M package.json -L package-lock.json --strategy in-place
   ```
   Always run the project's test/build command (`npm test` / `npm run build`) after dependency upgrades to confirm zero regressions.

---

## 4. Generating a Standard CycloneDX SBOM

When preparing for compliance or container packaging, generate a **CycloneDX JSON SBOM** (`sbom.cdx.json`) from the deterministic lockfile:

```bash
# Node.js (npm 10+ built-in — zero external package downloads or lifecycle scripts)
npm sbom --sbom-format=cyclonedx --package-lock-only --omit=dev > sbom.cdx.json
```
*(For Python, use `cyclonedx-py environment` or `requirements` into `sbom.cdx.json`.)*
