#!/usr/bin/env python3
"""
Collect cloud logs into a local directory.

Usage examples:
  python tools/collect_cloud_logs.py --provider gcp --bucket my-gcs-bucket --out data/logs/gcp --gcp-access-token "$GCP_ACCESS_TOKEN" --gcp-project my-project

Supports providing an OAuth2 access token via --gcp-access-token or GCP_ACCESS_TOKEN env var.
"""

from __future__ import annotations
import argparse
import os
import sys
import pathlib
import logging
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


def collect_gcp(bucket: str, prefix: str, out_dir: str, access_token: Optional[str] = None, project: Optional[str] = None):
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPIError

    token = access_token or os.environ.get("GCP_ACCESS_TOKEN")
    project = project or os.environ.get("GCP_PROJECT")

    client = None
    if token:
        try:
            from google.oauth2.credentials import Credentials
            creds = Credentials(token=token)
            log.info("Using provided GCP access token for authentication")
            client = storage.Client(credentials=creds, project=project)
        except Exception as e:
            log.error("Failed to construct GCP client with access token: %s", e)
            raise
    else:
        log.info("No GCP access token provided; attempting Application Default Credentials")
        client = storage.Client(project=project)

    ensure_dir(out_dir)
    downloaded = 0

    try:
        blobs = client.list_blobs(bucket, prefix=prefix or None)
        for blob in blobs:
            key = blob.name
            rel_path = key[len(prefix) :] if prefix and key.startswith(prefix) else key
            target = os.path.join(out_dir, rel_path)
            ensure_dir(os.path.dirname(target) or out_dir)
            try:
                log.info("Downloading gs://%s/%s -> %s", bucket, key, target)
                blob.download_to_filename(target)
                downloaded += 1
            except GoogleAPIError as e:
                log.error("Failed to download %s: %s", key, e)
    except Exception as e:
        log.error("GCP list/download error: %s", e)

    log.info("GCP: downloaded %d objects", downloaded)


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


def main():
    p = argparse.ArgumentParser(description="Collect cloud logs into a local directory")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 bucket or GCS bucket name")
    p.add_argument("--container", help="Azure storage container name")
    p.add_argument("--prefix", default="", help="Prefix/key prefix to filter objects")
    p.add_argument("--out", required=True, help="Local output directory")
    p.add_argument("--gcp-access-token", help="GCP OAuth2 access token (can also be provided via GCP_ACCESS_TOKEN env var)")
    p.add_argument("--gcp-project", help="GCP project id (optional, can also be provided via GCP_PROJECT env var)")
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
            collect_gcp(args.bucket, args.prefix, out_dir, access_token=args.gcp_access_token, project=args.gcp_project)
        elif args.provider == "azure":
            if not args.container:
                p.error("--container is required for azure")
            collect_azure(args.container, args.prefix, out_dir)
    except Exception as e:
        log.exception("Failed to collect logs: %s", e)
        sys.exit(2)


if __name__ == "__main__":
    main()
