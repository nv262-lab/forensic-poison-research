#!/usr/bin/env bash
set -euo pipefail

# Inputs (export these in your workflow before calling the script)
# AWS_DEFAULT_REGION, AWS_LOG_BUCKET (optional)
# GCP_REGION, GCP_LOG_BUCKET (optional), GCP_PROJECT, GCP_SA_KEY (if using service account)

run_id="${GITHUB_RUN_ID:-0}"

# --- AWS setup ---
AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
AWS_BUCKET="${AWS_LOG_BUCKET:-rag-forensic-logs-${run_id}}"

export AWS_DEFAULT_REGION="$AWS_REGION"
echo "Using AWS region: $AWS_REGION"
echo "Using S3 bucket: $AWS_BUCKET"

# Create S3 bucket with special-case for us-east-1
if aws s3api head-bucket --bucket "$AWS_BUCKET" 2>/dev/null; then
  echo "S3 bucket exists: $AWS_BUCKET"
else
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$AWS_BUCKET" || true
  else
    aws s3api create-bucket --bucket "$AWS_BUCKET" --create-bucket-configuration LocationConstraint="$AWS_REGION" || true
  fi

  # Wait / retry until bucket is available (short loop)
  for i in 1 2 3 4 5; do
    if aws s3api head-bucket --bucket "$AWS_BUCKET" 2>/dev/null; then
      echo "Created/verified bucket: $AWS_BUCKET"
      break
    fi
    echo "Waiting for bucket to become available..."
    sleep 2
  done
fi

# Enable versioning (ignore errors)
aws s3api put-bucket-versioning --bucket "$AWS_BUCKET" --versioning-configuration Status=Enabled || true

TRAIL_NAME="rag-forensic-trail-${run_id}"
aws cloudtrail create-trail --name "$TRAIL_NAME" --s3-bucket-name "$AWS_BUCKET" || true
aws cloudtrail put-event-selectors --trail-name "$TRAIL_NAME" --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::'"$AWS_BUCKET"'/"]}]}]' || true
aws cloudtrail start-logging --name "$TRAIL_NAME" || true

echo "AWS_LOG_BUCKET=$AWS_BUCKET" >> "$GITHUB_ENV"

# --- GCP setup ---
# Default to us-central1
GCP_REGION="${GCP_REGION:-us-central1}"
GCP_BUCKET="${GCP_LOG_BUCKET:-rag-forensic-logs-${run_id}}"

echo "Using GCP region: $GCP_REGION"
echo "Using GCS bucket: $GCP_BUCKET"

if [ -n "${GCP_SA_KEY:-}" ]; then
  echo "$GCP_SA_KEY" > /tmp/gcp_key.json
  export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp_key.json
  gcloud auth activate-service-account --key-file=/tmp/gcp_key.json --project="${GCP_PROJECT:-}" || true
fi

if gsutil ls -b "gs://$GCP_BUCKET" >/dev/null 2>&1; then
  echo "GCS bucket exists: $GCP_BUCKET"
else
  # Create bucket with location set to GCP_REGION (us-central1 is valid)
  gsutil mb -p "${GCP_PROJECT:-}" -c STANDARD -l "$GCP_REGION" "gs://$GCP_BUCKET" || true

  # Wait / retry until bucket is available
  for i in 1 2 3 4 5; do
    if gsutil ls -b "gs://$GCP_BUCKET" >/dev/null 2>&1; then
      echo "Created/verified GCS bucket: $GCP_BUCKET"
      break
    fi
    echo "Waiting for GCS bucket to become available..."
    sleep 2
  done
fi

gsutil versioning set on "gs://$GCP_BUCKET" || true

SINK_NAME="rag-forensic-sink-${run_id}"
gcloud logging sinks create "$SINK_NAME" "storage.googleapis.com/$GCP_BUCKET" --project="${GCP_PROJECT:-}" --log-filter='resource.type="gcs_bucket" OR protoPayload.methodName:("storage.objects.insert" OR "storage.objects.update")' || true

echo "GCP_LOG_BUCKET=$GCP_BUCKET" >> "$GITHUB_ENV"

echo "Cloud log buckets configured: AWS=$AWS_BUCKET GCP=$GCP_BUCKET"
