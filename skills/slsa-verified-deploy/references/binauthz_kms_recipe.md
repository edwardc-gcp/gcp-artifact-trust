# Google Cloud KMS & Binary Authorization Reference Recipe

Note: GA `gcloud container binauthz attestations sign-and-create` supports legacy PGP keys only. For **Cloud KMS asymmetric keys** (production standard), always use `create-signature-payload` + `gcloud kms asymmetric-sign` + `attestations create` as shown below.

## 1. Enable Required Google Cloud APIs

```bash
# Note: Enabling containerscanning.googleapis.com triggers automatic Artifact Analysis OS + language
# vulnerability scanning when new container digests are pushed (US$0.26 per unique new image digest).
gcloud services enable \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  containerscanning.googleapis.com \
  cloudkms.googleapis.com \
  containeranalysis.googleapis.com \
  binaryauthorization.googleapis.com \
  run.googleapis.com \
  --project="${PROJECT_ID}"
```

## 2. One-Time Setup: KMS Signing Key, Note, and Attestor

Set environment variables (`PROJECT_ID`, `REGION`, `ATTESTOR_ID="artifact-trust-attestor"`, `KEYRING="artifact-trust-keyring"`, `KEY_NAME="attestor-signing-key"`, `KEY_VERSION="1"`):

```bash
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
NOTE_ID="${ATTESTOR_ID}-note"
BINAUTHZ_SA="service-${PROJECT_NUMBER}@gcp-sa-binaryauthorization.iam.gserviceaccount.com"

# 0. Materialize the Binary Authorization service agent on newly enabled projects
gcloud beta services identity create \
  --service=binaryauthorization.googleapis.com \
  --project="${PROJECT_ID}" || true

# 1. Create KMS keyring and ECDSA P-256 asymmetric signing key
gcloud kms keyrings create "${KEYRING}" \
  --location="${REGION}" \
  --project="${PROJECT_ID}" || true
gcloud kms keys create "${KEY_NAME}" \
  --keyring="${KEYRING}" \
  --location="${REGION}" \
  --purpose="asymmetric-signing" \
  --default-algorithm="ec-sign-p256-sha256" \
  --project="${PROJECT_ID}" || true

# 2. Register Container Analysis Note
curl -sSf -X POST \
  "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/?noteId=${NOTE_ID}" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  -d "{\"attestation\":{\"hint\":{\"human_readable_name\":\"GCP Artifact Trust Attestor\"}}}" || true

# 3. Create Attestor and attach the Cloud KMS public key (triggers human confirmation via PreToolUse hook)
gcloud container binauthz attestors create "${ATTESTOR_ID}" \
  --attestation-authority-note="${NOTE_ID}" \
  --attestation-authority-note-project="${PROJECT_ID}" \
  --project="${PROJECT_ID}" || true

gcloud container binauthz attestors public-keys add \
  --attestor="${ATTESTOR_ID}" \
  --keyversion-project="${PROJECT_ID}" \
  --keyversion-location="${REGION}" \
  --keyversion-keyring="${KEYRING}" \
  --keyversion-key="${KEY_NAME}" \
  --keyversion="${KEY_VERSION}" \
  --project="${PROJECT_ID}" || true

# 4. Grant Binary Authorization service agent verifier access on the attestor and occurrences viewer access on the note
gcloud container binauthz attestors add-iam-policy-binding "${ATTESTOR_ID}" \
  --member="serviceAccount:${BINAUTHZ_SA}" \
  --role="roles/binaryauthorization.attestorsVerifier" \
  --project="${PROJECT_ID}"

curl -sSf -X POST \
  "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/${NOTE_ID}:setIamPolicy" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  -d "{\"policy\":{\"bindings\":[{\"role\":\"roles/containeranalysis.notes.occurrences.viewer\",\"members\":[\"serviceAccount:${BINAUTHZ_SA}\"]}]}}" >/dev/null
```

## 3. Enforce Require-Attestation Policy (Triggers User Confirmation)

```bash
cat > /tmp/binauthz-policy.yaml <<EOF
globalPolicyEvaluationMode: ENABLE
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
    - projects/${PROJECT_ID}/attestors/${ATTESTOR_ID}
name: projects/${PROJECT_ID}/policy
EOF

gcloud container binauthz policy import /tmp/binauthz-policy.yaml --project="${PROJECT_ID}"
rm -f /tmp/binauthz-policy.yaml
```

## 4. Sign Attestation for Verified Image Digest & Deploy to Cloud Run

Only run after confirming **SLSA provenance**, **OSV clean scan**, **Artifact Analysis container scan (`FINISHED_SUCCESS` + zero fixable `CRITICAL` vulnerabilities)**, and (if present) **CodeMender clean scan**:

> Base Linux distributions (such as Debian `bookworm-slim`) routinely carry unfixed upstream `LOW`/`MEDIUM` OS advisories (`not_fixed_vulnerability_count`). Gate KMS signing on `FINISHED_SUCCESS` + zero fixable `CRITICAL` vulnerabilities alongside clean `osv-scanner` lockfile results.

```bash
# 0. Verify Artifact Analysis OS + package scan completed (poll up to ~2m if run immediately after push)
for i in {1..12}; do
  SCAN_STATUS="$(gcloud artifacts docker images describe "${IMAGE_WITH_DIGEST}" \
    --project="${PROJECT_ID}" \
    --show-package-vulnerability \
    --format='value(discovery_summary.discovery[0].discovery.analysisStatus)' 2>/dev/null || true)"
  [ "${SCAN_STATUS}" = "FINISHED_SUCCESS" ] && break
  echo "Waiting for Artifact Analysis scan (status=${SCAN_STATUS:-PENDING})..."
  sleep 10
done
gcloud artifacts docker images describe "${IMAGE_WITH_DIGEST}" \
  --project="${PROJECT_ID}" \
  --show-package-vulnerability \
  --format="yaml(discovery_summary, package_vulnerability_summary)"

mkdir -p .artifact-trust
PUBLIC_KEY_ID="$(gcloud container binauthz attestors describe "${ATTESTOR_ID}" \
  --project="${PROJECT_ID}" \
  --format='value(userOwnedGrafeasNote.publicKeys[0].id)')"

# 1. Generate canonical BinAuthz payload bound to the immutable sha256 digest
gcloud container binauthz create-signature-payload \
  --artifact-url="${IMAGE_WITH_DIGEST}" \
  --project="${PROJECT_ID}" > .artifact-trust/payload.json

# 2. Sign SHA-256 digest with Cloud KMS
gcloud kms asymmetric-sign \
  --location="${REGION}" \
  --keyring="${KEYRING}" \
  --key="${KEY_NAME}" \
  --version="${KEY_VERSION}" \
  --digest-algorithm=sha256 \
  --input-file=.artifact-trust/payload.json \
  --signature-file=.artifact-trust/payload.sig \
  --project="${PROJECT_ID}"

# 3. Attach and validate attestation against the attestor
gcloud container binauthz attestations create \
  --artifact-url="${IMAGE_WITH_DIGEST}" \
  --attestor="projects/${PROJECT_ID}/attestors/${ATTESTOR_ID}" \
  --payload-file=.artifact-trust/payload.json \
  --signature-file=.artifact-trust/payload.sig \
  --public-key-id="${PUBLIC_KEY_ID}" \
  --validate \
  --project="${PROJECT_ID}"

# 4. Deploy to Cloud Run with Binary Authorization enabled
gcloud run deploy "${SERVICE_NAME}" \
  --image="${IMAGE_WITH_DIGEST}" \
  --region="${REGION}" \
  --binary-authorization=default \
  --platform=managed \
  --project="${PROJECT_ID}"
```

## 5. Red-Team Gate Verification (Prove Unsigned Images Are Blocked)

To verify that rogue or unattested images cannot bypass CI/SLSA checks, push or reference an unattested digest `${UNSIGNED_IMAGE_WITH_DIGEST}` and attempt deployment:

```bash
# Expected outcome: Deployment fails with Binary Authorization admission denial
gcloud run deploy "${SERVICE_NAME}" \
  --image="${UNSIGNED_IMAGE_WITH_DIGEST}" \
  --region="${REGION}" \
  --binary-authorization=default \
  --project="${PROJECT_ID}"
```
