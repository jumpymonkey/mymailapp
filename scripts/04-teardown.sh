#!/usr/bin/env bash
set -euo pipefail

export CLOUDSDK_CORE_DISABLE_PROMPTS=1

PROJECT_ID="${PROJECT_ID:?ERROR: Set PROJECT_ID environment variable (e.g. export PROJECT_ID=my-gcp-project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-mymailapp}"
AR_REPO="${AR_REPO:-mymailapp}"
BUILD_BUCKET="${PROJECT_ID}-${SERVICE_NAME}-build"

RUNNER_SA="mymailapp-runner@${PROJECT_ID}.iam.gserviceaccount.com"
BUILDER_SA="mymailapp-builder@${PROJECT_ID}.iam.gserviceaccount.com"

read -rp "Type '${PROJECT_ID}' to confirm teardown of MyMailApp GCP resources: " CONFIRM
if [[ "${CONFIRM}" != "${PROJECT_ID}" ]]; then
  echo "Aborted."
  exit 1
fi

gcloud run services delete "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --quiet || true
gcloud artifacts repositories delete "${AR_REPO}" --location="${REGION}" --project="${PROJECT_ID}" --quiet || true
gcloud storage rm --recursive "gs://${BUILD_BUCKET}" --project="${PROJECT_ID}" --quiet || true

for SECRET in mymailapp-oauth-client-id mymailapp-oauth-client-secret mymailapp-session-key; do
  gcloud secrets delete "${SECRET}" --project="${PROJECT_ID}" --quiet || true
done

gcloud iam service-accounts delete "${RUNNER_SA}" --project="${PROJECT_ID}" --quiet || true
gcloud iam service-accounts delete "${BUILDER_SA}" --project="${PROJECT_ID}" --quiet || true

echo "==> Teardown complete."
