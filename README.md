# GCP Artifact Trust Plugin (`gcp-artifact-trust`)

`gcp-artifact-trust` is a lightweight **software supply chain security harness** for AI coding agents. While [`codemender-security`](https://github.com/edwardc-gcp/codemender-security) secures **first-party application code** (*Trust the Code*), `gcp-artifact-trust` secures **everything you pull in, build, and ship to Cloud Run** (*Trust the Artifact*).

Built on the open [Agent Plugins specification](https://agent-plugins.org/), it runs across **Google Antigravity (`agy`)**, **Anthropic Claude Code (`claude`)**, and **OpenAI Codex (`codex`)**.

---

## ✨ Why a Thin Harness?

AI coding assistants move fast, which exposes three supply-chain blind spots:
1. **Dependency Slopsquatting & Lifecycle Hijacking**: Agents can install hallucinated package names or trigger malicious `postinstall` / `setup.py` scripts (such as the *s1ngularity* attack weaponizing local AI CLIs).
2. **Fragile Container & CI Recipes**: Agents default to mutable `:latest` tags, `root` containers, and unpinned GitHub Actions (`@v4` instead of 40-char commit SHAs).
3. **Bypassable Deployments**: Even with CI scans, anyone with deploy permissions can push an unverified local image unless production enforces cryptographic provenance.

Instead of wrapping standard tools in heavy black-box scripts, `gcp-artifact-trust` combines:
* **Deterministic `<2ms` `PreToolUse` Guard ([`scripts/pre_tool_guard.sh`](./scripts/pre_tool_guard.sh))**: Blocks Node.js/Python installs missing `--ignore-scripts` / `--only-binary=:all:`, and forces interactive human confirmation (`force_ask`) before mutating GCP Binary Authorization policies, disabling `--binary-authorization`, or installing binaries.
* **Zero-Key Reputation Checker ([`pkg_trust_check.sh`](./skills/dependency-trust/scripts/pkg_trust_check.sh))**: Queries Google **deps.dev** and **OSV.dev** before installation to block non-existent hallucinated packages, newly published (`< 7` days) releases, `MAL-*` malware, and `HIGH`/`CRITICAL` CVEs.
* **Two Focused Agent Skills**:
  * [`dependency-trust`](./skills/dependency-trust/SKILL.md): Pre-install trust checks, native `osv-scanner` lockfile auditing & guided upgrades, and CycloneDX SBOM generation.
  * [`slsa-verified-deploy`](./skills/slsa-verified-deploy/SKILL.md): `Dockerfile`/CI hardening, isolated **Google Cloud Build SLSA Level 3** provenance verification, optional joint verification with `codemender-security` SARIF reports, Cloud KMS asymmetric attestation signing, and **Cloud Run Binary Authorization** enforcement.

---

## 🚀 Installation

| Agent | Skills | Safety hook (`pre_tool_guard.sh`) | Always-on rule |
| :--- | :--- | :--- | :--- |
| Google Antigravity | ✅ | ✅ via [`hooks.json`](./hooks.json) | ✅ via [`rules/`](./rules/artifact-trust-safety.md) |
| Anthropic Claude Code | ✅ | ✅ via [`hooks/hooks.json`](./hooks/hooks.json) | — |
| OpenAI Codex | ✅ | ✅ via [`hooks/hooks.json`](./hooks/hooks.json) (trust in `/hooks`) | — |

### Google Antigravity (`agy`)
```bash
agy plugin install https://github.com/edwardc-gcp/gcp-artifact-trust.git
```

### Anthropic Claude Code (`claude`)
```bash
claude plugin marketplace add edwardc-gcp/gcp-artifact-trust
claude plugin install gcp-artifact-trust@gcp-artifact-trust
```

### OpenAI Codex (`codex`)
```bash
codex plugin marketplace add edwardc-gcp/gcp-artifact-trust
```
*(Then install **GCP Artifact Trust** from `/plugins` and trust the safety hook in `/hooks`.)*

---

## 🔑 Prerequisites

1. **Python 3** (pre-installed on Cloud Shell, macOS, and standard Linux distributions) for `deps.dev` / `OSV.dev` queries (no API keys required).
2. **`osv-scanner` CLI**: Ask your agent to *"check my gcp-artifact-trust environment"*—[`install_osv.sh`](./skills/dependency-trust/scripts/install_osv.sh) dynamically resolves the latest SLSA3 GitHub release, asks for your consent, verifies `osv-scanner_SHA256SUMS` (and `multiple.intoto.jsonl` when `slsa-verifier` is present), and installs to `~/.local/bin/osv-scanner`.
3. **Google Cloud SDK (`gcloud`)** authenticated with a project (`gcloud auth login` / ADC) when using `slsa-verified-deploy` for Cloud Build SLSA Level 3, Cloud KMS, Binary Authorization, and Cloud Run.

---

## 🧪 Self-Validation

```bash
bash scripts/validate_plugin.sh
```

## 📄 License

Apache-2.0 (see [`LICENSE`](./LICENSE)).
