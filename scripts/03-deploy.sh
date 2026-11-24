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

echo "==> [1/4] Running local quality gates (ruff + pytest)..."
uv run ruff check .
uv run ruff format --check .
uv run pytest

PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
APP_BASE_URL="https://${SERVICE_NAME}-${PROJECT_NUMBER}.${REGION}.run.app"
IMAGE_TAG="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo 'local')"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/web:${IMAGE_TAG}"

echo "==> [2/4] Building container via Cloud Build -> ${IMAGE_URI}..."
gcloud builds submit . \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --tag="${IMAGE_URI}" \
  --service-account="projects/${PROJECT_ID}/serviceAccounts/${BUILDER_SA}" \
  --gcs-source-staging-dir="gs://${BUILD_BUCKET}/source" \
  --gcs-log-dir="gs://${BUILD_BUCKET}/logs"

echo "==> [3/4] Deploying '${SERVICE_NAME}' to Cloud Run Gen2 (${REGION})..."
gcloud run deploy "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_URI}" \
  --service-account="${RUNNER_SA}" \
  --no-invoker-iam-check \
  --execution-environment=gen2 \
  --cpu=1 \
  --memory=512Mi \
  --concurrency=20 \
  --min-instances=0 \
  --max-instances=3 \
  --cpu-throttling \
  --timeout=60s \
  --set-env-vars="ENVIRONMENT=production,APP_BASE_URL=${APP_BASE_URL}" \
  --set-secrets="GOOGLE_CLIENT_ID=mymailapp-oauth-client-id:latest,GOOGLE_CLIENT_SECRET=mymailapp-oauth-client-secret:latest,SESSION_ENCRYPTION_KEY=mymailapp-session-key:latest"

echo "==> [4/4] Running HTTP smoke verification against ${APP_BASE_URL}..."
HEALTH_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "${APP_BASE_URL}/health")"
AUTH_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "${APP_BASE_URL}/")"

if [[ "${HEALTH_CODE}" != "200" || "${AUTH_CODE}" != "302" ]]; then
  echo "ERROR: Smoke check failed (/health=${HEALTH_CODE}, /=${AUTH_CODE})." >&2
  exit 1
fi

echo "==> Deployment verified! Open: ${APP_BASE_URL}"
