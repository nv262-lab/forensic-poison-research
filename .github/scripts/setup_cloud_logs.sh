#!/usr/bin/env bash
set -euo pipefail

# Required env:
# - GCP_PROJECT
# - GCP_LOG_BUCKET (optional)
# - GCP_LOG_SINK_NAME (optional)
# gcloud is expected to be authenticated and project set via setup-gcloud in workflow

GCP_PROJECT="${GCP_PROJECT:-}"
GCP_LOG_BUCKET="${GCP_LOG_BUCKET:-}"
GCP_LOG_SINK_NAME="${GCP_LOG_SINK_NAME:-}"
GCP_REGION="${GCP_REGION:-}"

echo "setup_cloud_logs.sh starting..."
echo "GCP_PROJECT=${GCP_PROJECT:-<not-set>}"
echo "GCP_LOG_BUCKET=${GCP_LOG_BUCKET:-<not-set>}"
echo "GCP_LOG_SINK_NAME=${GCP_LOG_SINK_NAME:-<not-set>}"

if [ -z "$GCP_PROJECT" ]; then
  echo "GCP_PROJECT is not set; skipping GCP log bucket setup"
  exit 0
fi

if [ -z "$GCP_LOG_BUCKET" ]; then
  echo "GCP_LOG_BUCKET is not set; nothing to do for GCP logs"
  exit 0
fi

# Ensure bucket exists
if ! gsutil ls -b "gs://${GCP_LOG_BUCKET}" >/dev/null 2>&1; then
  echo "Bucket gs://${GCP_LOG_BUCKET} does not exist; creating..."
  if [ -n "${GCP_REGION:-}" ]; then
    gsutil mb -p "$GCP_PROJECT" -l "${GCP_REGION}" "gs://${GCP_LOG_BUCKET}"
  else
    gsutil mb -p "$GCP_PROJECT" "gs://${GCP_LOG_BUCKET}"
  fi
else
  echo "Bucket gs://${GCP_LOG_BUCKET} exists"
fi

# If a sink name is provided, find its writerIdentity and grant permission
if [ -n "$GCP_LOG_SINK_NAME" ]; then
  echo "Looking up writerIdentity for sink ${GCP_LOG_SINK_NAME} in project ${GCP_PROJECT}"
  WRITER_IDENTITY=$(gcloud logging sinks describe "$GCP_LOG_SINK_NAME" --project="$GCP_PROJECT" --format="value(writerIdentity)" || true)
  if [ -z "$WRITER_IDENTITY" ]; then
    echo "No writerIdentity found for sink ${GCP_LOG_SINK_NAME}; ensure sink exists"
    exit 0
  fi
  echo "sink writerIdentity: ${WRITER_IDENTITY}"

  if echo "$WRITER_IDENTITY" | grep -q '^serviceAccount:'; then
    PRINCIPAL="$WRITER_IDENTITY"
  else
    PRINCIPAL="serviceAccount:${WRITER_IDENTITY}"
  fi

  echo "Granting roles/storage.objectCreator to ${PRINCIPAL} on gs://${GCP_LOG_BUCKET}"
  gsutil iam ch "${PRINCIPAL}:roles/storage.objectCreator" "gs://${GCP_LOG_BUCKET}"
  echo "Permission granted."
fi
