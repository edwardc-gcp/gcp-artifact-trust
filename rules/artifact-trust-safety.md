---
trigger: always_on
description: Pre-install package reputation checks, lifecycle-script blocks, and SLSA / Binary Authorization guardrails.
---

# Supply Chain & Artifact Trust Guardrails

1. **Safe Dependency Ingestion**: Before adding any third-party package, run [pkg_trust_check.sh](../skills/dependency-trust/scripts/pkg_trust_check.sh) (`npm` or `pypi`) and read `dependency-trust`. Always pass `--ignore-scripts` for Node.js installs (`npm`, `pnpm`, `yarn`) and `--only-binary=:all:` for Python installs (`pip`, `uv`).
2. **Hard Prohibitions**: NEVER bypass lifecycle script blocks (`--foreground-scripts`), install external binaries (`osv-scanner`), mutate GCP Binary Authorization policies/attestors, or disable Cloud Run `--binary-authorization` without explicit per-invocation user confirmation; read `slsa-verified-deploy` before containerizing or deploying.
