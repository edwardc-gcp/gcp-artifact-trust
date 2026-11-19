# Maintainer & Agent Guide (`gcp-artifact-trust`)

`gcp-artifact-trust` intentionally follows a **Thin Harness** architecture:
* Keep deterministic safety boundaries in [scripts/pre_tool_guard.sh](scripts/pre_tool_guard.sh) (`<2ms` fast-path, zero hard dependencies, full POSIX fallback without `jq` or `python3`).
* Keep API-backed pre-install reputation lookups in [skills/dependency-trust/scripts/pkg_trust_check.sh](skills/dependency-trust/scripts/pkg_trust_check.sh).
* Do **not** wrap clean, stateless CLIs (`osv-scanner`, `gcloud`) in opaque shell wrappers—document idiomatic commands in [skills/dependency-trust/SKILL.md](skills/dependency-trust/SKILL.md) and [skills/slsa-verified-deploy/SKILL.md](skills/slsa-verified-deploy/SKILL.md) so coding agents can inspect outputs and adapt directly.

## Validation

Before committing any change to this repository, run the automated validation suite:

```bash
bash scripts/validate_plugin.sh
```

`validate_plugin.sh` verifies:
1. Zero hardcoded personal home directory paths.
2. Shell syntax (`bash -n`) and executable permissions.
3. Self-contained skill compliance (no `../../` or install-specific paths inside `skills/*/SKILL.md`) and [Agent Skills](https://agentskills.io/specification) frontmatter schema.
4. `PreToolUse` hook decision matrix across **Antigravity**, **Claude Code**, **Codex**, and minimal POSIX environments (`jq` and `python3` disabled).
5. Offline mock tests for `pkg_trust_check.sh` (404 slopsquatting, `<7d` cooldown, `MAL-*` malware block, and clean pass).
6. Manifest version parity and relative Markdown link integrity.
