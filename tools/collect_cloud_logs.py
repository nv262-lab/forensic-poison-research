#!/usr/bin/env python3
"""
Collect cloud logs from AWS S3, GCP GCS, or Azure Blob Storage (non-interactive, no gcloud).

Important:
- GCP: uses ONLY an OAuth2 access token (env GCP_ACCESS_TOKEN or --gcp-access-token).
  This script will NOT call gcloud or attempt interactive OAuth flows.
- AWS: reads credentials from environment or instance profile (no interactive prompts).
- Azure: uses AZURE_STORAGE_CONNECTION_STRING.

Outputs downloads into --out and writes summary to data/logs/summary.json.
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
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs_no_interactive")


def ensure_dir(p: str | Path):
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)


def retry(fn, tries=3, delay=1, backoff=2, name="operation"):
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


# ---------------- AWS ----------------
def discover_or_create_aws_bucket(preferred: Optional[str] = None) -> Optional[str]:
    try:
        import boto3
        from botocore.exceptions import ClientError

        if preferred:
            return preferred
        for name in ("AWS_LOG_BUCKET", "TF_VAR_tf_state_bucket", "AWS_LOG_BUCKET_DEFAULT"):
            v = os.environ.get(name)
            if v:
                log.info("Using AWS bucket from env %s=%s", name, v)
                return v

        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        prefix = os.environ.get("AWS_LOG_BUCKET_DEFAULT", "rag-forensic-logs")
        for b in resp.get("Buckets", []):
            nm = b.get("Name", "")
            if nm.startswith(prefix):
                log.info("Discovered AWS bucket by listing: %s", nm)
                return nm

        default = os.environ.get("AWS_LOG_BUCKET_DEFAULT")
        if default and os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
            region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
            try:
                kwargs = {"Bucket": default}
                if region != "us-east-1":
                    kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
                s3.create_bucket(**kwargs)
                log.info("Created S3 bucket %s in %s (best-effort)", default, region)
                return default
            except ClientError as ce:
                log.warning("Failed to create default S3 bucket %s: %s", default, ce)
    except Exception as e:
        log.debug("AWS discovery/create failed: %s", e)
    return None


def _attempt_fix_aws_bucket_policy(bucket: str) -> bool:
    try:
        import boto3
        from botocore.exceptions import ClientError

        s3 = boto3.client("s3")
        sts = boto3.client("sts")
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
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    ensure_dir(out_dir)

    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        log.warning("head_bucket failed for %s: %s", bucket, getattr(e, "response", {}))
        if os.environ.get("AWS_GRANT_MEMBER") or os.environ.get("AWS_GRANT_CANONICAL_ID"):
            ok = _attempt_fix_aws_bucket_policy(bucket)
            if ok:
                try:
                    s3.head_bucket(Bucket=bucket)
                except Exception:
                    log.error("Still cannot access bucket after attempting policy changes.")
                    raise
        else:
            raise

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
                    retry(dl, tries=3, delay=1, backoff=2, name=f"s3-download {key}")
                    downloaded += 1
                    log.info("Downloaded s3://%s/%s -> %s", bucket, key, target)
                except Exception as e:
                    log.error("Failed to download s3://%s/%s: %s", bucket, key, e)
    except ClientError as e:
        log.error("S3 listing failed: %s", e)
        raise
    log.info("AWS: total downloaded %d files", downloaded)


# ---------------- GCP (REST-only, token required) ----------------
import requests  # used for REST calls


def _gcp_list_objects_rest(bucket: str, prefix: str, token: str) -> requests.Response:
    from urllib.parse import quote_plus
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/o"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"prefix": prefix} if prefix else {}
    return requests.get(url, headers=headers, params=params, timeout=30)


def _gcp_download_object_rest(bucket: str, name: str, token: str, out_path: str) -> bool:
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


def _gcp_get_iam_policy_rest(bucket: str, token: str) -> Optional[Dict[str, Any]]:
    from urllib.parse import quote_plus
    url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/iam"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if r.status_code == 200:
        return r.json()
    log.warning("Failed to get bucket IAM policy: %s %s", r.status_code, r.text)
    return None


def _gcp_set_iam_policy_rest(bucket: str, policy: Dict[str, Any], token: str) -> bool:
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
    ensure_dir(out_dir)
    if not token:
        raise RuntimeError("GCP_ACCESS_TOKEN is required for GCP provider (non-interactive).")

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
        log.warning("GCP REST returned 401 Unauthorized for provided token.")
        member = os.environ.get("GCP_GRANT_MEMBER")
        if member:
            if _gcp_add_binding_rest(bucket, member, "roles/storage.objectViewer", token):
                log.info("Added viewer binding via REST; retrying listing")
                r2 = _gcp_list_objects_rest(bucket, prefix, token)
                if r2.status_code == 200:
                    items = r2.json().get("items", [])
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
                        except Exception as e:
                            log.error("Download error for %s: %s", name, e)
                    log.info("GCP: downloaded %d objects after IAM change", downloaded)
                    return
            log.error("Token is unauthorized and attempt to add IAM binding failed or token lacks permission to set IAM.")
        raise RuntimeError("GCP listing failed and token unauthorized (401).")
    log.error("GCP REST returned %s: %s", r.status_code, r.text)
    raise RuntimeError(f"GCP listing failed with status {r.status_code}")


# ---------------- Azure ----------------
def collect_azure(container: str, prefix: str, out_dir: str):
    from azure.storage.blob import ContainerClient
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
                retry(dl, tries=3, delay=1, backoff=2, name=f"azure-download {key}")
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


# ---------------- summary ----------------
def parse_logs_and_summarize(root: Path, out_file: Path):
    summary: Dict[str, Any] = {"total_files": 0, "total_events": 0, "errors": []}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        summary["total_files"] += 1
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "AccessDenied" in text or "access denied" in text.lower():
            summary["errors"].append(str(p))
        summary["total_events"] += max(0, len([l for l in text.splitlines() if l.strip()]))
    ensure_dir(out_file.parent)
    out_file.write_text(json.dumps(summary, indent=2))
    log.info("Wrote summary to %s", out_file)
    return summary


# ---------------- main ----------------
def main():
    p = argparse.ArgumentParser(description="Collect cloud logs (non-interactive, GCP uses only access token)")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 or GCS bucket name")
    p.add_argument("--container", help="Azure container name")
    p.add_argument("--prefix", default="", help="Prefix to filter")
    p.add_argument("--out", required=True, help="Local output directory")
    p.add_argument("--gcp-access-token", help="GCP access token (overrides env GCP_ACCESS_TOKEN)")
    args = p.parse_args()

    out_dir = Path(args.out)
    ensure_dir(out_dir)

    try:
        if args.provider == "aws":
            bucket = args.bucket or discover_or_create_aws_bucket()
            if not bucket:
                p.error("AWS bucket not specified and none discovered/creatable")
            collect_aws(bucket, args.prefix, str(out_dir))
        elif args.provider == "gcp":
            bucket = args.bucket or os.environ.get("GCP_LOG_BUCKET") or os.environ.get("GCP_LOG_BUCKET_DEFAULT")
            if not bucket:
                p.error("GCP bucket not specified and none provided in env")
            token = args.gcp_access_token or os.environ.get("GCP_ACCESS_TOKEN")
            if not token:
                p.error("GCP_ACCESS_TOKEN must be set in env or passed via --gcp-access-token (non-interactive mode)")
            collect_gcp(bucket, args.prefix, str(out_dir), token)
        elif args.provider == "azure":
            container = args.container or os.environ.get("AZURE_LOG_CONTAINER")
            if not container:
                p.error("Azure container not specified and AZURE_LOG_CONTAINER not set")
            collect_azure(container, args.prefix, str(out_dir))
    except SystemExit:
        raise
    except Exception as e:
        log.error("Failed to collect logs: %s", e)
        log.debug(traceback.format_exc())
        sys.exit(2)

    try:
        parse_logs_and_summarize(out_dir, Path("data/logs/summary.json"))
    except Exception as e:
        log.warning("Failed to parse logs and write summary: %s", e)


if __name__ == "__main__":
    main()
