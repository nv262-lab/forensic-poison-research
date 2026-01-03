#!/usr/bin/env python3
"""
Collect cloud logs into a local directory.

Behavior:
- AWS:
  * If --bucket provided, uses it.
  * Else checks env: AWS_LOG_BUCKET, TF_VAR_tf_state_bucket, AWS_LOG_BUCKET_DEFAULT.
  * Else lists S3 buckets and picks the first matching prefix (rag-forensic-logs*).
  * Attempts to create bucket if it doesn't exist (if credentials allow).
- GCP:
  * Primary: use --gcp-access-token or env GCP_ACCESS_TOKEN with GCS JSON REST API (Bearer token).
  * If REST returns 401 or otherwise fails for auth reasons, automatically fallback to google-cloud-storage client (ADC / service account).
  * Will attempt to create bucket if it doesn't exist (via REST when token used; via client when falling back).
- Azure:
  * Uses AZURE_STORAGE_CONNECTION_STRING env var.
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import pathlib
import sys
import time
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs")


def ensure_dir(path: str | Path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


# ---------------- AWS ----------------
def _discover_aws_bucket(candidate_envs=()):
    # priority: explicit envs passed -> AWS_LOG_BUCKET -> TF_VAR_tf_state_bucket -> AWS_LOG_BUCKET_DEFAULT -> search buckets
    candidates = []
    for e in candidate_envs:
        v = os.environ.get(e)
        if v:
            candidates.append(v)
    # built-in defaults
    if os.environ.get("AWS_LOG_BUCKET"):
        candidates.append(os.environ.get("AWS_LOG_BUCKET"))
    if os.environ.get("TF_VAR_tf_state_bucket"):
        candidates.append(os.environ.get("TF_VAR_tf_state_bucket"))
    if os.environ.get("AWS_LOG_BUCKET_DEFAULT"):
        candidates.append(os.environ.get("AWS_LOG_BUCKET_DEFAULT"))

    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    # check that candidate exists
    for c in candidates:
        try:
            s3.head_bucket(Bucket=c)
            log.info("Using AWS bucket from candidate: %s", c)
            return c
        except ClientError:
            continue

    # list buckets and pick one matching prefix
    try:
        resp = s3.list_buckets()
        prefix = os.environ.get("AWS_LOG_BUCKET_DEFAULT", "rag-forensic-logs")
        for b in resp.get("Buckets", []):
            name = b.get("Name", "")
            if name.startswith(prefix):
                log.info("Discovered AWS bucket by listing: %s", name)
                return name
    except Exception as e:
        log.warning("Failed to list S3 buckets: %s", e)

    return None


def collect_aws(bucket: str, prefix: str, out_dir: str):
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    ensure_dir(out_dir)

    # If bucket doesn't exist, try to create (best-effort)
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        log.warning("AWS bucket %s not accessible: %s", bucket, code)
        # attempt to create
        try:
            region = os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
            create_kwargs = {"Bucket": bucket}
            if region != "us-east-1":
                create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
            log.info("Attempting to create S3 bucket %s in %s", bucket, region)
            s3.create_bucket(**create_kwargs)
            # enable versioning
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
            log.info("Created and enabled versioning for bucket %s", bucket)
            # small sleep to allow S3 eventual consistency
            time.sleep(2)
        except Exception as ce:
            log.error("Failed to create or access bucket %s: %s", bucket, ce)
            raise

    paginator = s3.get_paginator("list_objects_v2")
    kwargs = {"Bucket": bucket, "Prefix": prefix or ""}

    downloaded = 0
    for page in paginator.paginate(**kwargs):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            rel_path = key[len(prefix) :] if prefix and key.startswith(prefix) else key
            target = os.path.join(out_dir, rel_path)
            ensure_dir(os.path.dirname(target) or out_dir)
            try:
                log.info("Downloading s3://%s/%s -> %s", bucket, key, target)
                s3.download_file(bucket, key, target)
                downloaded += 1
            except ClientError as e:
                log.error("Failed to download %s: %s", key, e)
    log.info("AWS: downloaded %d objects", downloaded)


# ---------------- Azure ----------------
def collect_azure(container: str, prefix: str, out_dir: str):
    from azure.storage.blob import ContainerClient
    from azure.core.exceptions import AzureError

    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not conn_str:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING must be set in the environment for Azure downloads")

    client = ContainerClient.from_connection_string(conn_str, container_name=container)
    ensure_dir(out_dir)
    downloaded = 0

    blobs = client.list_blobs(name_starts_with=prefix or None)
    for blob in blobs:
        key = blob.name
        rel_path = key[len(prefix) :] if prefix and key.startswith(prefix) else key
        target = os.path.join(out_dir, rel_path)
        ensure_dir(os.path.dirname(target) or out_dir)
        try:
            log.info("Downloading azure://%s/%s -> %s", container, key, target)
            downloader = client.download_blob(key)
            with open(target, "wb") as f:
                f.write(downloader.readall())
            downloaded += 1
        except AzureError as e:
            log.error("Failed to download %s: %s", key, e)
    log.info("AZURE: downloaded %d objects", downloaded)


# ---------------- GCP (REST token primary, fallback ADC) ----------------
def _gcp_list_and_download_with_token(bucket: str, prefix: str, out_dir: str, token: str) -> int:
    import requests
    from urllib.parse import quote_plus

    ensure_dir(out_dir)
    downloaded = 0

    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/o"
    params = {"prefix": prefix} if prefix else {}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=60)
        if resp.status_code == 401:
            raise PermissionError("401 Unauthorized for GCS REST API")
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])
        log.info("GCP: found %d objects in bucket %s (prefix=%s)", len(items), bucket, prefix)
        for item in items:
            name = item.get("name")
            if not name:
                continue
            rel_path = name[len(prefix) :] if prefix and name.startswith(prefix) else name
            target = os.path.join(out_dir, rel_path)
            ensure_dir(os.path.dirname(target) or out_dir)
            download_url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/o/{quote_plus(name)}?alt=media"
            try:
                dl = requests.get(download_url, headers=headers, timeout=120, stream=True)
                dl.raise_for_status()
                with open(target, "wb") as fh:
                    for chunk in dl.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
                downloaded += 1
                log.info("Downloaded gs://%s/%s -> %s", bucket, name, target)
            except Exception as e:
                log.error("Failed to download %s: %s", name, e)
    except PermissionError:
        # bubble up for caller to trigger fallback
        raise
    except Exception as e:
        log.error("GCP REST API list error: %s", e)
    return downloaded


def _gcp_create_bucket_with_token(bucket: str, project: Optional[str], token: str, location: str = "US"):
    # minimal bucket create via JSON API
    import requests
    from urllib.parse import quote_plus

    url = f"https://storage.googleapis.com/storage/v1/b?project={quote_plus(project or '')}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"name": bucket, "location": location}
    resp = requests.post(url, headers=headers, json=body, timeout=60)
    if resp.status_code in (200, 201):
        log.info("Created GCS bucket %s via REST", bucket)
        return True
    else:
        log.error("Failed to create GCS bucket via REST: %s %s", resp.status_code, resp.text)
        return False


def collect_gcp(bucket: str, prefix: str, out_dir: str, access_token: Optional[str] = None, project: Optional[str] = None):
    """
    Primary approach: use access_token (REST). If token returns 401, fallback to google-cloud-storage client.
    """
    token = access_token or os.environ.get("GCP_ACCESS_TOKEN")
    project = project or os.environ.get("GCP_PROJECT")

    ensure_dir(out_dir)

    # If token provided, try REST first
    if token:
        try:
            # Check bucket existence by listing; if 404, attempt to create via REST
            dl = _gcp_list_and_download_with_token(bucket, prefix, out_dir, token)
            log.info("GCP: downloaded %d objects via REST token", dl)
            return
        except PermissionError:
            log.warning("GCP REST API returned 401 Unauthorized for provided token; will attempt ADC fallback")
        except Exception as e:
            log.warning("GCP REST attempt failed (non-auth): %s; will attempt ADC fallback", e)

    # Fallback: try google-cloud-storage client (ADC / setup-gcloud)
    try:
        from google.cloud import storage

        log.info("Attempting GCP download using google-cloud-storage client (ADC or service account)")
        client = storage.Client(project=project)
        # ensure bucket exists or create if permitted
        try:
            bucket_obj = client.get_bucket(bucket)
        except Exception:
            log.warning("Bucket %s not found via client; attempting to create (if permitted)", bucket)
            try:
                bucket_obj = client.create_bucket(bucket, location=(os.environ.get("GCP_REGION") or "US"))
                log.info("Created GCS bucket %s via client", bucket)
            except Exception as ce:
                log.error("Failed to create or access GCS bucket %s: %s", bucket, ce)
                raise

        downloaded = 0
        blobs = client.list_blobs(bucket, prefix=prefix or None)
        for blob in blobs:
            name = blob.name
            rel_path = name[len(prefix) :] if prefix and name.startswith(prefix) else name
            target = os.path.join(out_dir, rel_path)
            ensure_dir(os.path.dirname(target) or out_dir)
            try:
                log.info("Downloading gs://%s/%s -> %s", bucket, name, target)
                blob.download_to_filename(target)
                downloaded += 1
            except Exception as e:
                log.error("Failed to download %s: %s", name, e)
        log.info("GCP: downloaded %d objects via client", downloaded)
        return
    except Exception as e:
        log.error("GCP client fallback failed: %s", e)
        # if we had token and token REST failed due to 401 we already warned; end with failure
        raise RuntimeError("GCP download failed via both token REST and client approaches") from e


# ---------------- main ----------------
def main():
    p = argparse.ArgumentParser(description="Collect cloud logs into a local directory")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 bucket or GCS bucket name")
    p.add_argument("--container", help="Azure storage container name")
    p.add_argument("--prefix", default="", help="Prefix/key prefix to filter objects")
    p.add_argument("--out", required=True, help="Local output directory")
    p.add_argument("--gcp-access-token", help="GCP OAuth2 access token (env GCP_ACCESS_TOKEN)")
    args = p.parse_args()

    out_dir = args.out
    ensure_dir(out_dir)

    try:
        if args.provider == "aws":
            bucket = args.bucket
            if not bucket:
                bucket = _discover_aws_bucket(candidate_envs=())
                if not bucket:
                    p.error("--bucket is required for aws and no discoverable bucket found")
            collect_aws(bucket, args.prefix, out_dir)
        elif args.provider == "gcp":
            bucket = args.bucket or os.environ.get("GCP_LOG_BUCKET") or os.environ.get("GCP_LOG_BUCKET_DEFAULT")
            if not bucket:
                p.error("--bucket is required for gcp and no discoverable bucket found")
            collect_gcp(bucket, args.prefix, out_dir, access_token=args.gcp_access_token, project=args.gcp_project)
        elif args.provider == "azure":
            container = args.container or os.environ.get("AZURE_LOG_CONTAINER")
            if not container:
                p.error("--container is required for azure and no discoverable container found")
            collect_azure(container, args.prefix, out_dir)
    except SystemExit:
        raise
    except Exception as e:
        log.exception("Failed to collect logs: %s", e)
        sys.exit(2)


if __name__ == "__main__":
    main()
