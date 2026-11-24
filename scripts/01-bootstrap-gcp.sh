#!/usr/bin/env bash
set -euo pipefail

export CLOUDSDK_CORE_DISABLE_PROMPTS=1

PROJECT_ID="${PROJECT_ID:?ERROR: Set PROJECT_ID environment variable (e.g. export PROJECT_ID=my-gcp-project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-mymailapp}"
AR_REPO="${AR_REPO:-mymailapp}"
BUILD_BUCKET="${PROJECT_ID}-${SERVICE_NAME}-build"

RUNNER_SA_NAME="mymailapp-runner"
BUILDER_SA_NAME="mymailapp-builder"
RUNNER_SA="${RUNNER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
BUILDER_SA="${BUILDER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "==> [1/7] Verifying GCP project '${PROJECT_ID}' and active billing..."
BILLING_ENABLED="$(gcloud billing projects describe "${PROJECT_ID}" --format='value(billingEnabled)' 2>/dev/null || true)"
if [[ "${BILLING_ENABLED}" != "True" ]]; then
  echo "ERROR: Billing is not enabled on project '${PROJECT_ID}'." >&2
  echo "Link a billing account first:" >&2
  echo "  gcloud billing accounts list" >&2
  echo "  gcloud billing projects link ${PROJECT_ID} --billing-account=<ACCOUNT_ID>" >&2
  exit 1
fi

PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
DETERMINISTIC_URL="https://${SERVICE_NAME}-${PROJECT_NUMBER}.${REGION}.run.app"

echo "==> [2/7] Enabling required GCP APIs (including Gmail API)..."
gcloud services enable \
  gmail.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  iam.googleapis.com \
  --project="${PROJECT_ID}"

echo "==> [3/7] Provisioning Artifact Registry '${AR_REPO}' in '${REGION}'..."
if ! gcloud artifacts repositories describe "${AR_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="MyMailApp container images" \
    --project="${PROJECT_ID}"
fi

CLEANUP_POLICY_FILE="$(mktemp)"
LIFECYCLE_FILE="$(mktemp)"
trap 'rm -f "${CLEANUP_POLICY_FILE}" "${LIFECYCLE_FILE}"' EXIT

cat >"${CLEANUP_POLICY_FILE}" <<'EOF'
[
  {
    "name": "delete-older-than-7d",
    "action": {"type": "Delete"},
    "condition": {"tagState": "ANY", "olderThan": "604800s"}
  },
  {
    "name": "keep-latest-5",
    "action": {"type": "Keep"},
    "mostRecentVersions": {"keepCount": 5}
  }
]
EOF
gcloud artifacts repositories set-cleanup-policies "${AR_REPO}" \
  --location="${REGION}" \
  --project="${PROJECT_ID}" \
  --policy="${CLEANUP_POLICY_FILE}" \
  --quiet >/dev/null

echo "==> [4/7] Provisioning Cloud Build staging bucket 'gs://${BUILD_BUCKET}'..."
if ! gcloud storage buckets describe "gs://${BUILD_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${BUILD_BUCKET}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --project="${PROJECT_ID}"
fi

cat >"${LIFECYCLE_FILE}" <<'EOF'
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {"age": 1}
    }
  ]
}
EOF
gcloud storage buckets update "gs://${BUILD_BUCKET}" --lifecycle-file="${LIFECYCLE_FILE}" --project="${PROJECT_ID}" >/dev/null

echo "==> [5/7] Creating least-privilege Service Accounts..."
SA_CREATED=0
if ! gcloud iam service-accounts describe "${RUNNER_SA}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${RUNNER_SA_NAME}" \
    --display-name="MyMailApp Cloud Run Runtime SA" \
    --project="${PROJECT_ID}"
  SA_CREATED=1
fi
if ! gcloud iam service-accounts describe "${BUILDER_SA}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${BUILDER_SA_NAME}" \
    --display-name="MyMailApp Cloud Build SA" \
    --project="${PROJECT_ID}"
  SA_CREATED=1
fi
if [[ "${SA_CREATED}" -eq 1 ]]; then
  sleep 8
fi

echo "==> [6/7] Binding scoped IAM roles for Cloud Build SA..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${BUILDER_SA}" \
  --role="roles/logging.logWriter" \
  --condition=None \
  --quiet >/dev/null

gcloud storage buckets add-iam-policy-binding "gs://${BUILD_BUCKET}" \
  --member="serviceAccount:${BUILDER_SA}" \
  --role="roles/storage.admin" \
  --quiet >/dev/null

gcloud artifacts repositories add-iam-policy-binding "${AR_REPO}" \
  --location="${REGION}" \
  --project="${PROJECT_ID}" \
  --member="serviceAccount:${BUILDER_SA}" \
  --role="roles/artifactregistry.writer" \
  --quiet >/dev/null

echo "==> [7/7] Creating regional Secret Manager secrets & binding Runtime SA..."
SECRETS=(
  "mymailapp-oauth-client-id"
  "mymailapp-oauth-client-secret"
  "mymailapp-session-key"
)
for SECRET in "${SECRETS[@]}"; do
  if ! gcloud secrets describe "${SECRET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud secrets create "${SECRET}" \
      --replication-policy="user-managed" \
      --locations="${REGION}" \
      --project="${PROJECT_ID}"
  fi
  gcloud secrets add-iam-policy-binding "${SECRET}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${RUNNER_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet >/dev/null
done

EXISTING_KEY_VERSION="$(gcloud secrets versions list mymailapp-session-key --project="${PROJECT_ID}" --filter='state=ENABLED' --format='value(name)' --limit=1 2>/dev/null || true)"
if [[ -z "${EXISTING_KEY_VERSION}" ]]; then
  echo "    Generating initial 32-byte Fernet key for 'mymailapp-session-key'..."
  openssl rand 32 | base64 | tr -d '\n' | tr '+/' '-_' | \
    gcloud secrets versions add mymailapp-session-key --data-file=- --project="${PROJECT_ID}" >/dev/null
fi

cat <<EOF

================================================================================
Bootstrap complete for project '${PROJECT_ID}' (Project Number: ${PROJECT_NUMBER})
================================================================================
NEXT STEP — Manual OAuth 2.0 Console Checkpoint (One-Time, ~2 minutes):

1. Open Google Auth Platform in GCP Console for project '${PROJECT_ID}':
   https://console.cloud.google.com/auth/overview?project=${PROJECT_ID}

2. Configure Branding / Consent Screen:
   - App name: MyMailApp
   - Audience: External -> keep Publishing status as "Testing"
   - Test users: Add your personal Gmail address(es) (up to 100)
   - Data Access / Scopes: Add ONLY 'https://www.googleapis.com/auth/gmail.readonly'

3. Create OAuth Client (Clients -> Create Client):
   - Application type: Web application
   - Name: mymailapp-web
   - Authorized redirect URIs (add BOTH):
       http://localhost:8000/auth/callback
       ${DETERMINISTIC_URL}/auth/callback

4. Copy the Client ID and Client Secret, then run:
   ./scripts/02-store-oauth-secrets.sh
================================================================================
EOF
