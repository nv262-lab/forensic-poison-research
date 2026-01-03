#!/usr/bin/env bash
set -euo pipefail

# Creates/validates AWS S3 + CloudTrail and GCP GCS + logging sink.
# Uses env:
#   AWS_DEFAULT_REGION, AWS_LOG_BUCKET (optional)
#   AWS_ACCOUNT_ID (optional)
#   GCP_PROJECT, GCP_REGION, GCP_LOG_BUCKET (optional)
#   GCP_SA_KEY (optional)
#   CI_REPO (e.g., github.repository), CI_RUN_ID (e.g., github.run_id)

CI_REPO="${CI_REPO:-${GITHUB_REPOSITORY:-unknown_repo}}"
CI_RUN_ID="${CI_RUN_ID:-${GITHUB_RUN_ID:-0}}"
SAFE_REPO="$(echo "${CI_REPO}" | tr '/' '-' | tr '[:upper:]' '[:lower:]')"
run_id="${CI_RUN_ID}"

# --- AWS ---
AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
AWS_BUCKET="${AWS_LOG_BUCKET:-${SAFE_REPO}-logs-${run_id}}"
export AWS_DEFAULT_REGION="$AWS_REGION"

echo "Using AWS region: $AWS_REGION"
echo "Using S3 bucket: $AWS_BUCKET"

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI not found" >&2
  exit 1
fi

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)}"
if [ -z "$AWS_ACCOUNT_ID" ]; then
  echo "Unable to determine AWS account ID" >&2
  exit 1
fi

if ! aws s3api head-bucket --bucket "$AWS_BUCKET" 2>/dev/null; then
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$AWS_BUCKET"
  else
    aws s3api create-bucket --bucket "$AWS_BUCKET" --create-bucket-configuration LocationConstraint="$AWS_REGION"
  fi
  for i in {1..10}; do
    if aws s3api head-bucket --bucket "$AWS_BUCKET" 2>/dev/null; then
      echo "Created/verified bucket: $AWS_BUCKET"
      break
    fi
    echo "Waiting for bucket to become available..."
    sleep 2
  done
else
  echo "S3 bucket exists: $AWS_BUCKET"
fi

aws s3api put-bucket-versioning --bucket "$AWS_BUCKET" --versioning-configuration Status=Enabled >/dev/null 2>&1 || true

cat > /tmp/cloudtrail_policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck20150319",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${AWS_BUCKET}"
    },
    {
      "Sid": "AWSCloudTrailWrite20150319",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${AWS_BUCKET}/AWSLogs/${AWS_ACCOUNT_ID}/*",
      "Condition": { "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" } }
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket "$AWS_BUCKET" --policy file:///tmp/cloudtrail_policy.json >/dev/null 2>&1 || true

TRAIL_NAME="${SAFE_REPO}-trail-${run_id}"
if ! aws cloudtrail describe-trails --trail-name-list "$TRAIL_NAME" --query "trailList" | grep -q "$TRAIL_NAME"; then
  aws cloudtrail create-trail --name "$TRAIL_NAME" --s3-bucket-name "$AWS_BUCKET" >/dev/null 2>&1 || true
fi

for i in {1..5}; do
  if aws cloudtrail put-event-selectors --trail-name "$TRAIL_NAME" --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::'"$AWS_BUCKET"'/"]}]}]' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
aws cloudtrail start-logging --name "$TRAIL_NAME" >/dev/null 2>&1 || true

echo "AWS_LOG_BUCKET=$AWS_BUCKET" >> "$GITHUB_ENV"
echo "AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID" >> "$GITHUB_ENV"

# --- GCP ---
GCP_REGION="${GCP_REGION:-us-central1}"
GCP_BUCKET="${GCP_LOG_BUCKET:-${SAFE_REPO}-gcs-logs-${run_id}}"

echo "Using GCP region: $GCP_REGION"
echo "Using GCS bucket: $GCP_BUCKET"

if ! command -v gcloud >/dev/null 2>&1 || ! command -v gsutil >/dev/null 2>&1; then
  echo "gcloud/gsutil not found" >&2
  exit 1
fi

if [ -n "${GCP_SA_KEY:-}" ]; then
  echo "$GCP_SA_KEY" > /tmp/gcp_key.json
  export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp_key.json
  gcloud auth activate-service-account --key-file=/tmp/gcp_key.json --project="${GCP_PROJECT:-}" >/dev/null 2>&1 || true
fi

if ! gcloud projects describe "${GCP_PROJECT}" >/dev/null 2>&1; then
  echo "GCP project ${GCP_PROJECT} not found or inaccessible" >&2
  exit 1
fi

if ! gsutil ls -b "gs://$GCP_BUCKET" >/dev/null 2>&1; then
  if ! gsutil mb -p "${GCP_PROJECT}" -c STANDARD -l "${GCP_REGION}" "gs://$GCP_BUCKET" 2>/tmp/gsutil_err.txt; then
    sed -n '1,200p' /tmp/gsutil_err.txt
    gsutil mb -p "${GCP_PROJECT}" -c STANDARD -l "US" "gs://$GCP_BUCKET"
  fi
  for i in {1..10}; do
    if gsutil ls -b "gs://$GCP_BUCKET" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
fi

gsutil versioning set on "gs://$GCP_BUCKET" >/dev/null 2>&1 || true

SINK_NAME="${SAFE_REPO}-sink-${run_id}"
if ! gcloud logging sinks describe "$SINK_NAME" --project="${GCP_PROJECT}" >/dev/null 2>&1; then
  gcloud logging sinks create "$SINK_NAME" "storage.googleapis.com/$GCP_BUCKET" --project="${GCP_PROJECT}" --log-filter='resource.type="gcs_bucket" OR protoPayload.methodName:("storage.objects.insert" OR "storage.objects.update")' >/dev/null 2>&1 || true
fi

echo "GCP_LOG_BUCKET=$GCP_BUCKET" >> "$GITHUB_ENV"
echo "Cloud log buckets configured: AWS=$AWS_BUCKET GCP=$GCP_BUCKET"
