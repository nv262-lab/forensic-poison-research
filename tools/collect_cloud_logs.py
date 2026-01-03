#!/usr/bin/env python3
"""
Collect cloud logs from AWS S3, GCP GCS, and Azure Blob Storage (non-interactive).
Designed for CI (e.g., GitHub Actions). No interactive gcloud/auth flows are used.

Auth sources (non-interactive):
- GCP: must provide an OAuth2 access token via env GCP_ACCESS_TOKEN or --gcp-access-token.
- AWS: standard env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) or instance role.
- Azure: AZURE_STORAGE_CONNECTION_STRING.

Outputs:
- Downloads placed under --out/<provider>/
- Summary written to data/logs/summary.json

Dependencies:
- boto3, botocore (AWS)
- requests (GCP)
- azure-storage-blob (Azure)
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import pathlib
import sys
import time
import traceback
from pathlib import Path
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs_ci")

RETRY_TRIES = 3
RETRY_DELAY = 1
RETRY_BACKOFF = 2


def ensure_dir(p: str | Path):
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)


def retry(fn, tries=RETRY_TRIES, delay=RETRY_DELAY, backoff=RETRY_BACKOFF, name="operation"):
    last_exc = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            log.debug("Attempt %d/%d failed for %s: %s", i + 1, tries, name, e)
            time.sleep(delay)
            delay *= backoff
    raise last_exc


# ---------------- Summary ----------------
def write_summary(root: Path, out_file: Path):
    summary: Dict[str, Any] = {"total_files": 0, "providers": {}, "errors": []}
    if not root.exists():
        ensure_dir(root)
    for provider_dir in sorted(root.iterdir()):
        if not provider_dir.is_dir():
            continue
        p_summary = {"files": 0, "errors": []}
        for p in provider_dir.rglob("*"):
            if p.is_file():
                p_summary["files"] += 1
                try:
                    txt = p.read_text(errors="ignore")
                    if "AccessDenied" in txt or "access denied" in txt.lower():
                        p_summary["errors"].append(str(p))
                except Exception:
                    pass
        summary["providers"][provider_dir.name] = p_summary
        summary["total_files"] += p_summary["files"]
    ensure_dir(out_file.parent)
    out_file.write_text(json.dumps(summary, indent=2))
    log.info("Wrote summary to %s", out_file)


# ---------------- AWS ----------------
def discover_or_create_aws_bucket(preferred: Optional[str] = None) -> Optional[str]:
    try:
        import boto3
        from botocore.exceptions import ClientError
    except Exception:
        log.debug("boto3 not installed; skipping AWS discovery")
        return preferred

    if preferred:
        return preferred

    for name in ("AWS_LOG_BUCKET", "TF_VAR_tf_state_bucket", "AWS_LOG_BUCKET_DEFAULT"):
        v = os.environ.get(name)
        if v:
            log.info("Using AWS bucket from env %s=%s", name, v)
            return v

    try:
        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        prefix = os.environ.get("AWS_LOG_BUCKET_DEFAULT", "rag-forensic-logs")
        for b in resp.get("Buckets", []):
            nm = b.get("Name", "")
            if nm.startswith(prefix):
                log.info("Discovered AWS bucket by listing: %s", nm)
                return nm
    except Exception as e:
        log.debug("S3 list_buckets failed: %s", e)

    default = os.environ.get("AWS_LOG_BUCKET_DEFAULT")
    if default and os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        try:
            s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", None))
            region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
            kwargs = {"Bucket": default}
            if region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
            s3.create_bucket(**kwargs)
            log.info("Created S3 bucket %s in %s (best-effort)", default, region)
            return default
        except Exception as ce:
            log.warning("Failed to create default S3 bucket %s: %s", default, ce)
    return None


def _attempt_fix_aws_bucket_policy(bucket: str) -> bool:
    try:
        import boto3
        from botocore.exceptions import ClientError
        sts = boto3.client("sts")
        s3 = boto3.client("s3")
        caller = sts.get_caller_identity()
        acct = caller.get("Account")
        if not acct:
            log.warning("Cannot determine AWS account; skipping AWS policy fix")
            return False
        members = [f"arn:aws:iam::{acct}:root"]
        env_member = os.environ.get("AWS_GRANT_MEMBER")
        if env_member:
            members.append(env_member)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowReadToMembers",
                    "Effect": "Allow",
                    "Principal": {"AWS": members if len(members) > 1 else members[0]},
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::{bucket}/*"],
                },
                {
                    "Sid": "AllowListToMembers",
                    "Effect": "Allow",
                    "Principal": {"AWS": members if len(members) > 1 else members[0]},
                    "Action": ["s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}"],
                },
            ],
        }
        try:
            existing = s3.get_bucket_policy(Bucket=bucket)
            existing_policy = json.loads(existing["Policy"])
            sids = {s.get("Sid") for s in existing_policy.get("Statement", [])}
            for stmt in policy["Statement"]:
                if stmt["Sid"] not in sids:
                    existing_policy["Statement"].append(stmt)
            new_policy = existing_policy
        except ClientError:
            new_policy = policy
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(new_policy))
        log.info("Applied bucket policy to %s (best-effort)", bucket)
        canonical = os.environ.get("AWS_GRANT_CANONICAL_ID")
        if canonical:
            try:
                acl = s3.get_bucket_acl(Bucket=bucket)
                grants = acl.get("Grants", [])
                grants.append({"Grantee": {"Type": "CanonicalUser", "ID": canonical}, "Permission": "READ"})
                s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Owner": acl["Owner"], "Grants": grants})
                log.info("Added canonical ACL grant to %s", bucket)
            except Exception:
                log.debug("ACL canonical grant failed", exc_info=True)
        time.sleep(1)
        return True
    except Exception as e:
        log.warning("AWS policy fix failed (likely insufficient privileges): %s", e)
        return False


def collect_aws(bucket: str, prefix: str, out_dir: str):
    try:
        import boto3
    except Exception:
        raise RuntimeError("boto3 is required for AWS collection but is not installed")
    s3 = boto3.client("s3")
    ensure_dir(out_dir)
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception as e:
        log.warning("head_bucket failed for %s: %s", bucket, getattr(e, "response", e))
        if os.environ.get("AWS_GRANT_MEMBER") or os.environ.get("AWS_GRANT_CANONICAL_ID"):
            ok = _attempt_fix_aws_bucket_policy(bucket)
            if ok:
                try:
                    s3.head_bucket(Bucket=bucket)
                except Exception:
                    raise RuntimeError("Still cannot access AWS bucket after attempting policy fix")
        raise RuntimeError(f"Cannot access AWS bucket {bucket}: {e}")

    paginator = s3.get_paginator("list_objects_v2")
    kwargs = {"Bucket": bucket, "Prefix": prefix or "", "PaginationConfig": {"PageSize": 1000}}
    downloaded = 0
    try:
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                target = os.path.join(out_dir, key)
                ensure_dir(os.path.dirname(target) or out_dir)
                def dl():
                    s3.download_file(bucket, key, target)
                try:
                    retry(dl, name=f"s3-download {key}")
                    downloaded += 1
                    log.info("Downloaded s3://%s/%s -> %s", bucket, key, target)
                except Exception as e:
                    log.error("Failed to download s3://%s/%s: %s", bucket, key, e)
    except Exception as e:
        raise RuntimeError(f"S3 listing/downloading failed: {e}")
    log.info("AWS: total downloaded %d files", downloaded)


# ---------------- GCP (REST-only) ----------------
try:
    import requests
except Exception:
    requests = None


def _gcp_list_objects_rest(bucket: str, prefix: str, token: str):
    if not requests:
        raise RuntimeError("requests library is required for GCP REST calls")
    from urllib.parse import quote_plus
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/o"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"prefix": prefix} if prefix else {}
    return requests.get(url, headers=headers, params=params, timeout=30)


def _gcp_download_object_rest(bucket: str, name: str, token: str, out_path: str) -> bool:
    if not requests:
        raise RuntimeError("requests library is required for GCP REST calls")
    qname = requests.utils.quote(name, safe="")
    dl_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{qname}?alt=media"
    r = requests.get(dl_url, headers={"Authorization": f"Bearer {token}"}, stream=True, timeout=120)
    if r.status_code == 200:
        ensure_dir(os.path.dirname(out_path) or out_path)
        with open(out_path, "wb") as fh:
            for ch in r.iter_content(8192):
                if ch:
                    fh.write(ch)
        return True
    log.warning("Failed to download gs://%s/%s: status %s", bucket, name, r.status_code)
    return False


def _gcp_get_iam_policy_rest(bucket: str, token: str):
    if not requests:
        raise RuntimeError("requests library is required for GCP REST calls")
    from urllib.parse import quote_plus
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/iam"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if r.status_code == 200:
        return r.json()
    log.warning("Failed to get bucket IAM policy: %s %s", r.status_code, r.text)
    return None


def _gcp_set_iam_policy_rest(bucket: str, policy: Dict[str, Any], token: str) -> bool:
    if not requests:
        raise RuntimeError("requests library is required for GCP REST calls")
    from urllib.parse import quote_plus
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/iam"
    r = requests.put(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=policy, timeout=30)
    if r.status_code == 200:
        return True
    log.warning("Failed to set bucket IAM policy: %s %s", r.status_code, r.text)
    return False


def _gcp_add_binding_rest(bucket: str, member: str, role: str, token: str) -> bool:
    pol = _gcp_get_iam_policy_rest(bucket, token)
    if pol is None:
        return False
    bindings = pol.get("bindings", [])
    for b in bindings:
        if b.get("role") == role:
            if member in b.get("members", []):
                log.info("Member %s already has role %s on %s", member, role, bucket)
                return True
            b["members"].append(member)
            pol["bindings"] = bindings
            return _gcp_set_iam_policy_rest(bucket, pol, token)
    bindings.append({"role": role, "members": [member]})
    pol["bindings"] = bindings
    return _gcp_set_iam_policy_rest(bucket, pol, token)


def collect_gcp(bucket: str, prefix: str, out_dir: str, token: str):
    if not requests:
        raise RuntimeError("requests library is required for GCP REST calls")
    ensure_dir(out_dir)
    if not token:
        raise RuntimeError("GCP access token required in non-interactive CI mode")

    r = _gcp_list_objects_rest(bucket, prefix, token)
    if r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        log.info("GCP REST: found %d objects", len(items))
        downloaded = 0
        for it in items:
            name = it.get("name")
            if not name:
                continue
            target = os.path.join(out_dir, name)
            try:
                ok = _gcp_download_object_rest(bucket, name, token, target)
                if ok:
                    downloaded += 1
                    log.info("Downloaded gs://%s/%s -> %s", bucket, name, target)
            except Exception as e:
                log.error("Download error for %s: %s", name, e)
        log.info("GCP: downloaded %d objects", downloaded)
        return

    if r.status_code == 401:
        log.error("GCP REST returned 401 Unauthorized for provided token. Ensure GCP_ACCESS_TOKEN is valid and has storage.objectViewer permissions.")
        raise RuntimeError("GCP token unauthorized (401)")

    log.error("GCP REST returned %s: %s", r.status_code, r.text)
    raise RuntimeError(f"GCP listing failed with status {r.status_code}")


# ---------------- Azure ----------------
def collect_azure(container: str, prefix: str, out_dir: str):
    try:
        from azure.storage.blob import ContainerClient
    except Exception:
        raise RuntimeError("azure-storage-blob is required for Azure collection but is not installed")

    ensure_dir(out_dir)
    conn = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not conn:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required for Azure downloads")
    client = ContainerClient.from_connection_string(conn, container_name=container)
    downloaded = 0
    try:
        blobs = client.list_blobs(name_starts_with=prefix or None)
        had = False
        for blob in blobs:
            had = True
            key = blob.name
            target = os.path.join(out_dir, key)
            ensure_dir(os.path.dirname(target) or out_dir)
            def dl():
                data = client.download_blob(key).readall()
                with open(target, "wb") as fh:
                    fh.write(data)
            try:
                retry(dl, name=f"azure-download {key}")
                downloaded += 1
                log.info("Downloaded azure://%s/%s -> %s", container, key, target)
            except Exception as e:
                log.error("Failed to download azure://%s/%s: %s", container, key, e)
        if not had:
            log.info("No blobs found in azure://%s with prefix '%s'", container, prefix or "")
        log.info("AZURE: downloaded %d objects", downloaded)
    except Exception as e:
        log.error("Azure list/download failed: %s", e)
        if os.environ.get("AZURE_MAKE_PUBLIC", "false").lower() == "true":
            try:
                client.set_container_access_policy(public_access="container")
                log.info("Set container public; retrying download")
                return collect_azure(container, prefix, out_dir)
            except Exception as e2:
                log.warning("Failed to set container ACL: %s", e2)
        raise


# ---------------- CLI / main ----------------
def main():
    p = argparse.ArgumentParser(description="Collect cloud logs (CI non-interactive)")
    p.add_argument("--providers", nargs="+", choices=["aws", "gcp", "azure"], default=["aws", "gcp", "azure"], help="Providers to collect from")
    p.add_argument("--bucket", help="S3 or GCS bucket name")
    p.add_argument("--container", help="Azure container name")
    p.add_argument("--prefix", default="", help="Prefix to filter")
    p.add_argument("--out", required=True, help="Local output directory (root for provider subdirs)")
    p.add_argument("--gcp-access-token", help="GCP access token (overrides env GCP_ACCESS_TOKEN)")
    args = p.parse_args()

    out_root = Path(args.out)
    ensure_dir(out_root)

    errors = []

    for provider in args.providers:
        try:
            if provider == "aws":
                aws_out = out_root / "aws"
                ensure_dir(aws_out)
                bucket = args.bucket or os.environ.get("AWS_LOG_BUCKET") or os.environ.get("AWS_LOG_BUCKET_DEFAULT")
                if not bucket:
                    bucket = discover_or_create_aws_bucket()
                if not bucket:
                    msg = "No AWS log bucket configured/discoverable. Set AWS_LOG_BUCKET or AWS_LOG_BUCKET_DEFAULT and ensure AWS credentials are present."
                    log.warning(msg)
                    errors.append({"provider": "aws", "error": msg})
                else:
                    log.info("Collecting AWS from bucket %s", bucket)
                    collect_aws(bucket, args.prefix, str(aws_out))
            elif provider == "gcp":
                gcp_out = out_root / "gcp"
                ensure_dir(gcp_out)
                bucket = args.bucket or os.environ.get("GCP_LOG_BUCKET") or os.environ.get("GCP_LOG_BUCKET_DEFAULT")
                if not bucket:
                    msg = "No GCP log bucket specified. Set --bucket or GCP_LOG_BUCKET/GCP_LOG_BUCKET_DEFAULT"
                    log.warning(msg)
                    errors.append({"provider": "gcp", "error": msg})
                else:
                    token = args.gcp_access_token or os.environ.get("GCP_ACCESS_TOKEN")
                    if not token:
                        msg = "GCP_ACCESS_TOKEN not provided. Set env GCP_ACCESS_TOKEN or pass --gcp-access-token"
                        log.warning(msg)
                        errors.append({"provider": "gcp", "error": msg})
                    else:
                        log.info("Collecting GCP from bucket %s", bucket)
                        collect_gcp(bucket, args.prefix, str(gcp_out), token)
            elif provider == "azure":
                az_out = out_root / "azure"
                ensure_dir(az_out)
                container = args.container or os.environ.get("AZURE_LOG_CONTAINER")
                if not container:
                    msg = "No Azure container specified. Set --container or AZURE_LOG_CONTAINER"
                    log.warning(msg)
                    errors.append({"provider": "azure", "error": msg})
                else:
                    log.info("Collecting Azure from container %s", container)
                    collect_azure(container, args.prefix, str(az_out))
        except Exception as e:
            tb = traceback.format_exc()
            log.error("Provider %s failed: %s\n%s", provider, e, tb)
            errors.append({"provider": provider, "error": str(e)})
            # continue to next provider

    try:
        write_summary(out_root, Path("data/logs/summary.json"))
    except Exception as e:
        log.warning("Failed to write summary: %s", e)

    if errors:
        log.info("Completed with errors: %s", errors)
        sys.exit(2)

    log.info("Completed successfully for all requested providers.")


if __name__ == "__main__":
    main()
