---
name: slsa-verified-deploy
description: Harden Dockerfiles and CI workflows for SLSA Level 3, build provenance-attested containers via Google Cloud Build, optionally verify CodeMender clean state, sign Cloud KMS attestations, and enforce Binary Authorization on Cloud Run.
compatibility: Requires gcloud CLI authenticated with a Google Cloud project (Cloud Build, Artifact Registry, Container Scanning, Cloud KMS, Binary Authorization, and Cloud Run APIs).
---

# SLSA Build Hardening & Binary Authorization Deployment

Use this skill when containerizing an application, hardening CI/CD workflows, generating SLSA Level 3 build provenance, signing cryptographic attestations, or deploying to Google Cloud Run with Binary Authorization enforcement.

## 1. Source & Container Supply-Chain Hardening (Agent Native Edit Checklist)

Before submitting a build, inspect and directly remediate `Dockerfile`, `cloudbuild.yaml`, and `.github/workflows/*.yml` against these four supply-chain rules:

1. **Immutable Base Image Digests (`Dockerfile`)**:
   * Replace mutable tags (`FROM node:22-bookworm-slim` or `:latest`) with SHA-256 pinned digests (`FROM node:22-bookworm-slim@sha256:<64-hex-digest>`). Resolve current official digests via `docker buildx imagetools inspect node:22-bookworm-slim`.
2. **Zero-Script Deterministic Builds, Build Ignores & Least Privilege (`Dockerfile`, `.dockerignore`, `.gcloudignore`)**:
   * Create `.dockerignore` and `.gcloudignore` excluding `node_modules/`, `dist/`, `.artifact-trust/`, and `*.sig` so local artifacts never leak into the Cloud Build context tarball or image layers.
   * Use multi-stage builds; install production dependencies only with `npm ci --omit=dev --ignore-scripts` (or `pip install --no-cache-dir --only-binary=:all: -r requirements.txt`).
   * Drop `root` before `CMD`/`ENTRYPOINT` (`USER node` or dedicated non-root UID `10001`).
3. **Commit-SHA Pinned GitHub Actions (`.github/workflows/*.yml`)**:
   * Pin every third-party `uses:` step to an immutable 40-character Git commit SHA with a version comment (`uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`), never mutable `@main` or `@v4` tags.
   * Keep `permissions:` read-only (`contents: read`) at workflow top level; grant `id-token: write` only on the job that authenticates via Google Cloud WIF.
4. **Verified SLSA Provenance in Cloud Build (`cloudbuild.yaml`)**:
   * Use Google's managed `gcr.io/cloud-builders/docker` builder (avoiding unpinned Docker Hub `latest` pulls), declare target `images:`, and set `options.requestedVerifyOption: VERIFIED` so Cloud Build emits signed **SLSA Build Level 3** provenance into Artifact Registry:
   ```yaml
   steps:
     - name: 'gcr.io/cloud-builders/docker'
       args: ['build', '-t', '${_IMAGE_URI}', '.']
   images:
     - '${_IMAGE_URI}'
   options:
     requestedVerifyOption: VERIFIED
     logging: CLOUD_LOGGING_ONLY
   ```

---

## 2. Isolated Cloud Build & SLSA Provenance Check

Never build production images on a local workstation. On projects created after mid-2024 where default Compute Engine SA IAM grants are disabled, provision a dedicated least-privilege builder service account (`slsa-builder-sa`) with `roles/logging.logWriter`, `roles/storage.objectViewer`, and `roles/artifactregistry.writer`, then submit to **Google Cloud Build** and capture the immutable `@sha256:` digest:

```bash
# 1. Submit build to isolated Cloud Build worker using least-privilege builder SA
gcloud builds submit --config=cloudbuild.yaml \
  --service-account="projects/${PROJECT_ID}/serviceAccounts/slsa-builder-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --substitutions="_IMAGE_URI=${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${APP}:${COMMIT_SHA}" \
  --project="${PROJECT_ID}" .

# 2. Resolve immutable sha256 digest and verify SLSA Build Level 3 provenance attachment
DIGEST="$(gcloud artifacts docker images describe \
  "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${APP}:${COMMIT_SHA}" \
  --project="${PROJECT_ID}" \
  --format='value(image_summary.digest)')"
IMAGE_WITH_DIGEST="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${APP}@${DIGEST}"

gcloud artifacts docker images describe "${IMAGE_WITH_DIGEST}" \
  --project="${PROJECT_ID}" \
  --show-provenance \
  --format="yaml(image_summary.slsa_build_level, provenance_summary)"
```

Confirm `image_summary.slsa_build_level` shows `SLSA_BUILD_LEVEL_3` (or `3`) and `provenance_summary.provenance` contains `kind: BUILD` (`inTotoSlsaProvenanceV1` from `https://cloudbuild.googleapis.com/GoogleHostedWorker`) before proceeding to attestation. Note that `gcloud builds submit .` proves isolated SLSA v1.0 Build Level 3 execution over the uploaded archive; for full Git source-anchored provenance in production CI/CD, trigger builds directly from a protected Git repository.

---

## 3. Adaptive Pre-Attestation Security Gate (OSV + Artifact Analysis + Optional CodeMender)

Before signing a deployment attestation with Cloud KMS, verify all applicable security gates pass on the exact commit being shipped:

1. **SLSA Provenance Gate**: Verified in Step 2 (`image_summary.slsa_build_level` Level 3 and `kind: BUILD` provenance present from Cloud Build).
2. **Two-Layer Vulnerability Verification (`osv-scanner` + Artifact Analysis)**:
   * **Pre-build lockfile gate (`osv-scanner`)**: Confirm `osv-scanner` reports zero unmitigated `CRITICAL`/`HIGH` application dependency vulnerabilities.
   * **Post-build container layer gate (Artifact Analysis)**: Run `gcloud artifacts docker images describe "${IMAGE_WITH_DIGEST}" --show-package-vulnerability --format="yaml(discovery_summary, package_vulnerability_summary)"` and confirm `analysisStatus: FINISHED_SUCCESS` across OS (`apt`/`apk`) and language layers with **zero fixable `CRITICAL` vulnerabilities**. (Note: Debian/Ubuntu base images normally report unfixed upstream `LOW`/`MEDIUM` OS entries, so do not require `total_vulnerability_count == 0` on OS layers.)
3. **Adaptive `codemender-security` Gate (When Present)**:
   * Check whether the workspace contains `.codemender/` or a recent `*.sarif` CodeMender report (or if the user requested joint verification).
   * If present, inspect the report to confirm **zero open Critical/High exploitable source vulnerabilities** remain unpatched. If open Critical/High findings exist, stop and remediate with `codemender-security` before signing!

---

## 4. Cloud KMS Attestation & Cloud Run Binary Authorization Enforcement

Follow the exact `gcloud` commands in [references/binauthz_kms_recipe.md](references/binauthz_kms_recipe.md) to:
1. Provision the Cloud KMS asymmetric signing key, Container Analysis note, Binary Authorization attestor (`artifact-trust-attestor`), and project policy (note: `pre_tool_guard.sh` requires explicit user approval on policy/attestor mutations).
2. Sign the exact `${IMAGE_WITH_DIGEST}` payload via `gcloud kms asymmetric-sign` and attach the attestation.
3. Deploy to Cloud Run with `--binary-authorization=default` (using `${IMAGE_WITH_DIGEST}`, never a mutable tag).
4. Optionally validate enforcement by attempting to deploy an unattested image and confirming Cloud Run rejects it (`IMAGE_ATTESTATION_FAILED`).
