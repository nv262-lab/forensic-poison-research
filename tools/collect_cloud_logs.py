#!/usr/bin/env python3
"""
Collect cloud logs into a local directory.

This version uses ONLY an OAuth2 access token for GCP (no service account files).
GCP auth:
 - Provide OAuth2 access token via --gcp-access-token or env GCP_ACCESS_TOKEN.
 - The script will use the GCS JSON REST API with Bearer token to list & download objects.

Usage examples:
  python tools/collect_cloud_logs.py --provider gcp --bucket my-gcs-bucket --out data/logs/gcp --gcp-access-token "$GCP_ACCESS_TOKEN"
  python tools/collect_cloud_logs.py --provider aws --bucket my-s3-bucket --out data/logs/aws
  python tools/collect_cloud_logs.py --provider azure --container rag-logs --out data/logs/azure

Note: For GCP this requires a valid access token with permission to list/read objects
(e.g., scope https://www.googleapis.com/auth/devstorage.read_only).
"""

from __future__ import annotations
import argparse
import base64
import json
import logging
import os
import pathlib
import sys
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs")


def ensure_dir(path: str | Path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


def collect_aws(bucket: str, prefix: str, out_dir: str):
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    kwargs = {"Bucket": bucket, "Prefix": prefix or ""}

    ensure_dir(out_dir)
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


# ---- GCP helpers: REST API only (requires access token) ----
def _gcp_list_and_download_with_token(bucket: str, prefix: str, out_dir: str, token: str) -> int:
    """
    Use GCS JSON API with Bearer token to list objects and download them.
    Returns number downloaded.
    """
    import requests
    from urllib.parse import quote_plus

    ensure_dir(out_dir)
    downloaded = 0

    # List objects
    params = {"prefix": prefix} if prefix else {}
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/o"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=60)
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
    except Exception as e:
        log.error("GCP REST API list error: %s", e)

    return downloaded


def collect_gcp(bucket: str, prefix: str, out_dir: str, access_token: Optional[str] = None):
    """
    Collect objects from a GCS bucket using only an access token.
    Raises if no token is provided.
    """
    token = access_token or os.environ.get("GCP_ACCESS_TOKEN")
    if not token:
        raise RuntimeError(
            "GCP access token required. Provide --gcp-access-token or set GCP_ACCESS_TOKEN env var."
        )

    log.info("Using provided GCP access token for REST API downloads")
    downloaded = _gcp_list_and_download_with_token(bucket, prefix, out_dir, token)
    log.info("GCP: downloaded %d objects via REST token", downloaded)


def main():
    p = argparse.ArgumentParser(description="Collect cloud logs into a local directory")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 bucket or GCS bucket name")
    p.add_argument("--container", help="Azure storage container name")
    p.add_argument("--prefix", default="", help="Prefix/key prefix to filter objects")
    p.add_argument("--out", required=True, help="Local output directory")
    p.add_argument("--gcp-access-token", help="GCP OAuth2 access token (can also be provided via GCP_ACCESS_TOKEN env var)")
    args = p.parse_args()

    out_dir = args.out
    ensure_dir(out_dir)

    try:
        if args.provider == "aws":
            if not args.bucket:
                p.error("--bucket is required for aws")
            collect_aws(args.bucket, args.prefix, out_dir)
        elif args.provider == "gcp":
            if not args.bucket:
                p.error("--bucket is required for gcp")
            collect_gcp(args.bucket, args.prefix, out_dir, access_token=args.gcp_access_token)
        elif args.provider == "azure":
            if not args.container:
                p.error("--container is required for azure")
            collect_azure(args.container, args.prefix, out_dir)
    except Exception as e:
        log.exception("Failed to collect logs: %s", e)
        sys.exit(2)


if __name__ == "__main__":
    main()
