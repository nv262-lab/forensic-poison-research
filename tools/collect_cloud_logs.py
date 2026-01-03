#!/usr/bin/env python3
"""
Collect cloud logs into a local directory.

Usage examples:
  python tools/collect_cloud_logs.py --provider aws --bucket my-bucket --prefix logs/ --out data/logs/aws
  python tools/collect_cloud_logs.py --provider gcp --bucket my-gcs-bucket --prefix logs/ --out data/logs/gcp
  python tools/collect_cloud_logs.py --provider azure --container rag-logs --out data/logs/azure
"""

import argparse
import os
import sys
import pathlib
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs")


def ensure_dir(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


def collect_aws(bucket, prefix, out_dir):
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


def collect_gcp(bucket, prefix, out_dir):
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPIError

    client = storage.Client()
    bucket_obj = client.bucket(bucket)
    blobs = client.list_blobs(bucket, prefix=prefix or None)

    ensure_dir(out_dir)
    downloaded = 0

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
    log.info("GCP: downloaded %d objects", downloaded)


def collect_azure(container, prefix, out_dir):
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
            with open(target, "wb") as f:
                stream = client.download_blob(key)
                stream.readinto(f)
            downloaded += 1
        except AzureError as e:
            log.error("Failed to download %s: %s", key, e)
    log.info("AZURE: downloaded %d objects", downloaded)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 bucket or GCS bucket name")
    p.add_argument("--container", help="Azure storage container name")
    p.add_argument("--prefix", default="", help="Prefix/key prefix to filter objects")
    p.add_argument("--out", required=True, help="Local output directory")
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
            collect_gcp(args.bucket, args.prefix, out_dir)
        elif args.provider == "azure":
            if not args.container:
                p.error("--container is required for azure")
            collect_azure(args.container, args.prefix, out_dir)
    except Exception as e:
        log.exception("Failed to collect logs: %s", e)
        sys.exit(2)


if _name_ == "_main_":
    main()
