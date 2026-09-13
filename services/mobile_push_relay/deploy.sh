#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 PROJECT_ID REGION SERVICE_ACCOUNT IMAGE_URI@sha256:DIGEST" >&2
  exit 2
fi

project_id="$1"
region="$2"
service_account="$3"
image_digest="$4"

if [[ ! "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "invalid Google Cloud project ID" >&2
  exit 2
fi
if [[ ! "$region" =~ ^[a-z][a-z0-9-]+[0-9]$ ]]; then
  echo "invalid Google Cloud region" >&2
  exit 2
fi
if [[ ! "$service_account" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
  echo "invalid service account email" >&2
  exit 2
fi
if [[ ! "$image_digest" =~ ^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "the runtime image must be pinned by a sha256 digest" >&2
  exit 2
fi
if ! command -v gcloud >/dev/null 2>&1; then
  echo "gcloud is required" >&2
  exit 127
fi

manifest="$(mktemp)"
trap 'rm -f "$manifest"' EXIT
sed \
  -e "s|__RELAY_PROJECT_ID__|$project_id|g" \
  -e "s|__RELAY_SERVICE_ACCOUNT__|$service_account|g" \
  -e "s|__RELAY_IMAGE_DIGEST__|$image_digest|g" \
  services/mobile_push_relay/cloud-run.service.yaml > "$manifest"

if grep -q '__RELAY_' "$manifest"; then
  echo "deployment manifest still contains an unresolved placeholder" >&2
  exit 2
fi

gcloud run services replace "$manifest" \
  --project "$project_id" \
  --region "$region" \
  --quiet
