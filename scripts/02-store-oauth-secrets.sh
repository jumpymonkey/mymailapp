#!/usr/bin/env bash
set -euo pipefail

export CLOUDSDK_CORE_DISABLE_PROMPTS=1

PROJECT_ID="${PROJECT_ID:?ERROR: Set PROJECT_ID environment variable (e.g. export PROJECT_ID=my-gcp-project)}"

put_secret_cleanly() {
  local secret_name="$1"
  local secret_value="$2"

  local old_versions
  old_versions="$(gcloud secrets versions list "${secret_name}" \
    --project="${PROJECT_ID}" \
    --filter='state=ENABLED' \
    --format='value(name)' 2>/dev/null || true)"

  printf '%s' "${secret_value}" | \
    gcloud secrets versions add "${secret_name}" --data-file=- --project="${PROJECT_ID}" >/dev/null

  for ver in ${old_versions}; do
    gcloud secrets versions disable "${ver}" --secret="${secret_name}" --project="${PROJECT_ID}" --quiet >/dev/null
  done
}

read -rp "Enter Google OAuth Client ID (ends with .apps.googleusercontent.com): " CLIENT_ID
read -rsp "Enter Google OAuth Client Secret (input hidden): " CLIENT_SECRET
echo ""

if [[ -z "${CLIENT_ID}" || -z "${CLIENT_SECRET}" ]]; then
  echo "ERROR: Both Client ID and Client Secret must be non-empty." >&2
  exit 1
fi

echo "==> Writing OAuth credentials to Secret Manager in '${PROJECT_ID}'..."
put_secret_cleanly "mymailapp-oauth-client-id" "${CLIENT_ID}"
put_secret_cleanly "mymailapp-oauth-client-secret" "${CLIENT_SECRET}"

echo "==> Secrets stored and prior versions disabled. Ready for './scripts/03-deploy.sh'."
