#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 PROJECT_ID REGION SERVICE IMAGE_URI@sha256:DIGEST" >&2
  exit 2
fi

project_id="$1"
region="$2"
service="$3"
expected_image="$4"

if [[ ! "$expected_image" =~ ^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "expected runtime image must be pinned by a sha256 digest" >&2
  exit 2
fi
if ! command -v gcloud >/dev/null 2>&1; then
  echo "gcloud is required" >&2
  exit 127
fi

service_yaml="$(mktemp)"
trap 'rm -f "$service_yaml"' EXIT
gcloud run services describe "$service" \
  --project "$project_id" \
  --region "$region" \
  --format=export > "$service_yaml"

grep -Fq "image: $expected_image" "$service_yaml" || {
  echo "Cloud Run is not serving the expected immutable image" >&2
  exit 1
}
grep -Eq 'image: [^[:space:]]+@sha256:[0-9a-f]{64}$' "$service_yaml" || {
  echo "Cloud Run image is not digest-pinned" >&2
  exit 1
}
grep -Eq 'serviceAccountName: [^[:space:]]+' "$service_yaml" || {
  echo "Cloud Run service account is missing" >&2
  exit 1
}
grep -Fq 'runAsNonRoot: true' "$service_yaml" || {
  echo "Cloud Run non-root policy is missing" >&2
  exit 1
}
grep -Fq 'readOnlyRootFilesystem: true' "$service_yaml" || {
  echo "Cloud Run read-only root policy is missing" >&2
  exit 1
}
grep -Fq 'mountPath: /tmp' "$service_yaml" || {
  echo "Cloud Run /tmp mount is missing" >&2
  exit 1
}
grep -Fq 'medium: Memory' "$service_yaml" || {
  echo "Cloud Run /tmp tmpfs policy is missing" >&2
  exit 1
}
grep -Fq 'name: RELAY_BACKEND' "$service_yaml" || {
  echo "Cloud Run Firestore backend setting is missing" >&2
  exit 1
}
if ! awk '
  /name: RELAY_BACKEND[[:space:]]*$/ {
    if (getline next_line > 0 && next_line ~ /value: firestore[[:space:]]*$/) found = 1
  }
  END { exit(found ? 0 : 1) }
' "$service_yaml"; then
  echo "Cloud Run relay backend is not Firestore" >&2
  exit 1
fi
grep -Fq 'run.googleapis.com/ingress: internal-and-cloud-load-balancing' "$service_yaml" || {
  echo "Cloud Run ingress is not the approved internal-and-cloud-load-balancing policy" >&2
  exit 1
}

echo "Cloud Run relay checks passed for $service"
