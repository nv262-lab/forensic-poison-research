#!/usr/bin/env python3
"""
Collect cloud logs into a local directory.

Features:
- AWS:
  * Use --bucket or AWS_LOG_BUCKET env var. If neither provided, tries to discover a bucket.
  * If CloudTrail objects are present, automatically restrict downloads to CloudTrail prefixes
    (e.g. AWSLogs/<account>/CloudTrail/...).
  * Attempts to create bucket if not present (best-effort).
- GCP:
  * Uses only access token (REST API) if provided; falls back to google-cloud-storage client when token auth fails.
- Azure:
  * Uses AZURE_STORAGE_CONNECTION_STRING env var.
"""

from __future__ import annotations
import argparse
import logging
import os
import pathlib
import sys
import time
from pathlib import Path
from typing import Optional, Iterable, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs")


def ensure_dir(path: str | Path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


# ---------------- AWS ----------------
def _discover_aws_bucket() -> Optional[str]:
    # Priority: explicit envs -> list buckets and pick prefixed one
    for name in ("AWS_LOG_BUCKET", "TF_VAR_tf_state_bucket", "AWS_LOG_BUCKET_DEFAULT"):
        v = os.environ.get(name)
        if v:
            log.info("Found AWS bucket in env %s=%s", name, v)
            return v

    try:
        import boto3

        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        prefix = os.environ.get("AWS_LOG_BUCKET_DEFAULT", "rag-forensic-logs")
        for b in resp.get("Buckets", []):
            name = b.get("Name", "")
            if name.startswith(prefix):
                log.info("Discovered AWS bucket by listing: %s", name)
                return name
    except Exception as e:
        log.warning("Failed to discover AWS buckets: %s", e)
    return None


def _find_cloudtrail_prefixes(s3_client, bucket: str, sample_limit: int = 100) -> Iterable[str]:
    """
    Heuristically find CloudTrail prefixes like AWSLogs/<account>/CloudTrail/.
    Returns an iterable of prefixes to use (may be empty).
    """
    paginator = s3_client.get_paginator("list_objects_v2")
    # look at top-level prefixes by requesting delimiter '/'
    try:
        pages = paginator.paginate(Bucket=bucket, Delimiter="/", PaginationConfig={"PageSize": 100})
        for page in pages:
            for p in page.get("CommonPrefixes", []):
                prefix = p.get("Prefix", "")
                # prefix like 'AWSLogs/' indicates CloudTrail logs could be under this tree
                if prefix.startswith("AWSLogs"):
                    # list deeper to discover account id + CloudTrail
                    subpages = paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/", PaginationConfig={"PageSize": 100})
                    for sp in subpages:
                        for spc in sp.get("CommonPrefixes", []):
                            subpref = spc.get("Prefix", "")
                            # expect AWSLogs/<account>/
                            # check for CloudTrail inside that account prefix
                            deeper = prefix + subpref.split(prefix, 1)[-1]
                            # search for CloudTrail marker
                            check_pages = paginator.paginate(Bucket=bucket, Prefix=subpref, Delimiter="/", PaginationConfig={"PageSize": 100})
                            for cp in check_pages:
                                for cpc in cp.get("CommonPrefixes", []):
                                    cpre = cpc.get("Prefix", "")
                                    if "CloudTrail" in cpre:
                                        # normalize to prefix up to CloudTrail/
                                        idx = cpre.find("CloudTrail")
                                        yield cpre[: idx + len("CloudTrail/")]
    except Exception:
        return ()
    return ()


def collect_aws(bucket: str, prefix: str, out_dir: str):
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    ensure_dir(out_dir)

    # ensure bucket exists or attempt create
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        log.warning("AWS bucket %s not accessible: %s", bucket, getattr(e, "response", {}))
        try:
            region = os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
            create_kwargs = {"Bucket": bucket}
            if region != "us-east-1":
                create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
            log.info("Attempting to create S3 bucket %s in %s", bucket, region)
            s3.create_bucket(**create_kwargs)
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
            time.sleep(2)
        except Exception as ce:
            log.error("Failed to create or access bucket %s: %s", bucket, ce)
            raise

    # Auto-detect CloudTrail prefixes if present and no explicit prefix passed
    effective_prefixes = [prefix] if prefix else []
    if not prefix:
        try:
            ct_prefixes = list(_find_cloudtrail_prefixes(s3, bucket))
            if ct_prefixes:
                log.info("Detected CloudTrail prefixes: %s", ct_prefixes)
                effective_prefixes = ct_prefixes
            else:
                log.info("No CloudTrail prefixes detected; will list entire bucket (use --prefix to narrow)")
                effective_prefixes = [""]
        except Exception as e:
            log.warning("CloudTrail detection failed: %s; defaulting to full bucket", e)
            effective_prefixes = [""]

    paginator = s3.get_paginator("list_objects_v2")
    downloaded = 0
    for eff_pref in effective_prefixes:
        kwargs = {"Bucket": bucket, "Prefix": eff_pref or ""}
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                rel_path = key[len(eff_pref) :] if eff_pref and key.startswith(eff_pref) else key
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


# ---------------- GCP (token primary, ADC fallback) ----------------
def _gcp_list_and_download_with_token(bucket: str, prefix: str, out_dir: str, token: str) -> int:
    import requests
    from urllib.parse import quote_plus

    ensure_dir(out_dir)
    downloaded = 0
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/o"
    params = {"prefix": prefix} if prefix else {}
    headers = {"Authorization": f"Bearer {token}"}
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
        dl = requests.get(download_url, headers=headers, timeout=120, stream=True)
        dl.raise_for_status()
        with open(target, "wb") as fh:
            for chunk in dl.iter_content(chunk_size=8192):
                if chunk:
                    fh.write(chunk)
        downloaded += 1
        log.info("Downloaded gs://%s/%s -> %s", bucket, name, target)
    return downloaded


def collect_gcp(bucket: str, prefix: str, out_dir: str, access_token: Optional[str] = None, project: Optional[str] = None):
    token = access_token or os.environ.get("GCP_ACCESS_TOKEN")
    project = project or os.environ.get("GCP_PROJECT")
    ensure_dir(out_dir)

    if token:
        try:
            dl = _gcp_list_and_download_with_token(bucket, prefix, out_dir, token)
            log.info("GCP: downloaded %d objects via REST token", dl)
            return
        except PermissionError:
            log.warning("GCP REST API returned 401 Unauthorized for provided token; will attempt ADC fallback")
        except Exception as e:
            log.warning("GCP REST attempt failed: %s; will attempt ADC fallback", e)

    try:
        from google.cloud import storage

        log.info("Attempting GCP download using google-cloud-storage client (ADC or service account)")
        client = storage.Client(project=project)
        blobs = client.list_blobs(bucket, prefix=prefix or None)
        downloaded = 0
        for blob in blobs:
            name = blob.name
            rel_path = name[len(prefix) :] if prefix and name.startswith(prefix) else name
            target = os.path.join(out_dir, rel_path)
            ensure_dir(os.path.dirname(target) or out_dir)
            blob.download_to_filename(target)
            downloaded += 1
            log.info("Downloaded gs://%s/%s -> %s", bucket, name, target)
        log.info("GCP: downloaded %d objects via client", downloaded)
        return
    except Exception as e:
        log.error("GCP client fallback failed: %s", e)
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
    p.add_argument("--gcp-project", help="GCP project id (optional, env GCP_PROJECT)")
    args = p.parse_args()

    out_dir = args.out
    ensure_dir(out_dir)

    try:
        if args.provider == "aws":
            bucket = args.bucket or os.environ.get("AWS_LOG_BUCKET") or _discover_aws_bucket()
            if not bucket:
                p.error("--bucket is required for aws and no discoverable bucket found")
            # If CloudTrail logs are present, collector will detect and restrict download automatically.
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
