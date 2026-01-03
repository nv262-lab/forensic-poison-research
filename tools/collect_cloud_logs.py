#!/usr/bin/env python3
"""
Collect cloud logs: auto-configure auth (best-effort), discover/configure buckets,
attempt permission fixes (only if credentials permit), download logs, and write a summary.

Supports AWS, GCP, Azure. See README-like notes at top of file for env vars needed.
"""
from _future_ import annotations
import argparse
import base64
import json
import logging
import os
import pathlib
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("collect_cloud_logs")


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


# ---------------- GCP ADC auto-config ----------------
def ensure_gcp_adc_from_env() -> Optional[str]:
    """
    If GCP_SA_KEY_JSON or GCP_SA_KEY_B64 present in env, write it to a temp file and set GOOGLE_APPLICATION_CREDENTIALS.
    Returns path to credentials file or None.
    """
    sa_json = os.environ.get("GCP_SA_KEY_JSON")
    sa_b64 = os.environ.get("GCP_SA_KEY_B64")
    if not sa_json and not sa_b64:
        return None
    try:
        if sa_b64:
            sa_json = base64.b64decode(sa_b64).decode("utf-8")
        creds_path = Path("/tmp/gcp_service_account.json")
        creds_path.write_text(sa_json)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_path)
        log.info("Wrote GCP service account JSON to %s and set GOOGLE_APPLICATION_CREDENTIALS", creds_path)
        # optionally run gcloud auth activate-service-account if gcloud exists (improves ADC local tools)
        try:
            subprocess.run(["gcloud", "auth", "activate-service-account", "--key-file", str(creds_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.info("Activated service account with gcloud (if gcloud present)")
        except Exception:
            # ignore if gcloud not present or fails
            pass
        return str(creds_path)
    except Exception as e:
        log.warning("Failed to write GCP service account JSON: %s", e)
        return None


# ---------------- AWS discovery / config helpers ----------------
def aws_env_configured() -> bool:
    return bool(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))


def discover_or_create_aws_bucket(preferred: Optional[str] = None) -> Optional[str]:
    """
    Try explicit bucket, then envs, then list S3 and pick candidate starting with prefix.
    If not found but AWS_LOG_BUCKET_DEFAULT present and we have write rights, try to create.
    """
    import boto3
    from botocore.exceptions import ClientError

    if preferred:
        return preferred
    for name in ("AWS_LOG_BUCKET", "TF_VAR_tf_state_bucket", "AWS_LOG_BUCKET_DEFAULT"):
        v = os.environ.get(name)
        if v:
            log.info("Using AWS bucket from env %s=%s", name, v)
            return v

    # list buckets
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

    # attempt to create default if provided and creds exist
    default = os.environ.get("AWS_LOG_BUCKET_DEFAULT")
    if default and aws_env_configured():
        try:
            region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
            s3 = boto3.client("s3", region_name=region)
            kwargs = {"Bucket": default}
            if region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
            s3.create_bucket(**kwargs)
            log.info("Created S3 bucket %s in %s (best-effort)", default, region)
            return default
        except ClientError as ce:
            log.warning("Failed to create bucket %s: %s", default, ce)
    return None


# ---------------- GCP helpers ----------------
def discover_gcp_bucket(preferred: Optional[str] = None) -> Optional[str]:
    if preferred:
        return preferred
    for name in ("GCP_LOG_BUCKET", "GCP_LOG_BUCKET_DEFAULT"):
        v = os.environ.get(name)
        if v:
            log.info("Using GCP bucket from env %s=%s", name, v)
            return v
    return None


# ---------------- Azure helpers ----------------
def discover_azure_container(preferred: Optional[str] = None) -> Optional[str]:
    if preferred:
        return preferred
    v = os.environ.get("AZURE_LOG_CONTAINER")
    if v:
        log.info("Using Azure container from env AZURE_LOG_CONTAINER=%s", v)
        return v
    return None


# ---------------- collectors (robust) ----------------
def collect_aws(bucket: str, prefix: str, out_dir: str):
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    ensure_dir(out_dir)
    # head bucket
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        log.warning("Cannot head_bucket %s: %s", bucket, getattr(e, "response", {}))
        # try to apply a permissive read policy if configured
        if os.environ.get("AWS_GRANT_MEMBER") or os.environ.get("AWS_GRANT_CANONICAL_ID"):
            _attempt_fix_aws_bucket_policy(bucket)
            try:
                s3.head_bucket(Bucket=bucket)
            except Exception:
                log.error("Still cannot access bucket after attempt to fix policy")
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
                    log.error("Failed to download %s: %s", key, e)
    except ClientError as e:
        log.error("S3 listing failed: %s", e)
        raise
    log.info("AWS: total downloaded %d files", downloaded)


def collect_gcp(bucket: str, prefix: str, out_dir: str, access_token: Optional[str] = None, project: Optional[str] = None):
    import requests
    ensure_dir(out_dir)
    token = access_token or os.environ.get("GCP_ACCESS_TOKEN")
    if token:
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o"
        params = {"prefix": prefix} if prefix else {}
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=30)
        if r.status_code == 200:
            items = r.json().get("items", [])
            log.info("GCP REST: found %d objects", len(items))
            dlcount = 0
            for it in items:
                name = it.get("name")
                if not name:
                    continue
                q = requests.utils.quote(name, safe="")
                dl = requests.get(f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{q}?alt=media", headers={"Authorization": f"Bearer {token}"}, stream=True, timeout=120)
                if dl.status_code == 200:
                    target = os.path.join(out_dir, name)
                    ensure_dir(os.path.dirname(target) or out_dir)
                    with open(target, "wb") as fh:
                        for ch in dl.iter_content(8192):
                            if ch:
                                fh.write(ch)
                    dlcount += 1
                    log.info("Downloaded gs://%s/%s -> %s", bucket, name, target)
                else:
                    log.warning("Failed to download %s: %s", name, dl.status_code)
            log.info("GCP: downloaded %d", dlcount)
            return
        elif r.status_code == 401:
            log.warning("GCP token unauthorized (401); ADC fallback attempted next")
        else:
            log.warning("GCP REST returned %s: %s", r.status_code, r.text)

    # ADC fallback
    try:
        from google.cloud import storage
        client = storage.Client(project=project)
        blobs = client.list_blobs(bucket, prefix=prefix or None)
        dl = 0
        for blob in blobs:
            target = os.path.join(out_dir, blob.name)
            ensure_dir(os.path.dirname(target) or out_dir)
            retry(lambda: blob.download_to_filename(target), tries=3, delay=1, backoff=2, name=f"gcs-download {blob.name}")
            dl += 1
            log.info("Downloaded gs://%s/%s -> %s", bucket, blob.name, target)
        log.info("GCP: downloaded %d via ADC client", dl)
        return
    except Exception as e:
        log.error("GCP ADC/client fallback failed: %s", e)
        raise RuntimeError("GCP download failed (no working auth)") from e


def collect_azure(container: str, prefix: str, out_dir: str):
    from azure.storage.blob import ContainerClient
    ensure_dir(out_dir)
    conn = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not conn:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING required for Azure")
    client = ContainerClient.from_connection_string(conn, container_name=container)
    downloaded = 0
    try:
        blobs = client.list_blobs(name_starts_with=prefix or None)
        had = False
        for b in blobs:
            had = True
            key = b.name
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
                log.error("Failed to download %s: %s", key, e)
        if not had:
            log.info("No blobs found in azure://%s with prefix '%s'", container, prefix or "")
        log.info("AZURE: downloaded %d objects", downloaded)
    except Exception as e:
        log.error("Azure list/download failed: %s", e)
        # attempt to set public if configured
        if os.environ.get("AZURE_MAKE_PUBLIC", "false").lower() == "true":
            try:
                client.set_container_access_policy(public_access="container")
                log.info("Set container public; retrying download")
                return collect_azure(container, prefix, out_dir)
            except Exception as e2:
                log.warning("Failed to set container ACL: %s", e2)
        raise


# ---------------- permission helper stubs (best-effort) ----------------
def _attempt_fix_aws_bucket_policy(bucket: str) -> bool:
    # same logic as prior scripts: attempt to set a read policy for account root and optional member
    try:
        import boto3
        from botocore.exceptions import ClientError
        sts = boto3.client("sts")
        s3 = boto3.client("s3")
        caller = sts.get_caller_identity()
        acct = caller.get("Account")
        if not acct:
            return False
        members = [f"arn:aws:iam::{acct}:root"]
        env_member = os.environ.get("AWS_GRANT_MEMBER")
        if env_member:
            members.append(env_member)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AllowReadToMembers", "Effect": "Allow", "Principal": {"AWS": members if len(members)>1 else members[0]}, "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
                {"Sid": "AllowListToMembers", "Effect": "Allow", "Principal": {"AWS": members if len(members)>1 else members[0]}, "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}"]},
            ]
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
        log.info("Applied/updated bucket policy on %s", bucket)
        canonical = os.environ.get("AWS_GRANT_CANONICAL_ID")
        if canonical:
            try:
                acl = s3.get_bucket_acl(Bucket=bucket)
                grants = acl.get("Grants", [])
                grants.append({"Grantee": {"Type":"CanonicalUser","ID":canonical}, "Permission":"READ"})
                s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Owner":acl["Owner"], "Grants":grants})
                log.info("Added canonical ACL grant to %s", bucket)
            except Exception:
                log.debug("Failed canonical ACL addition", exc_info=True)
        time.sleep(1)
        return True
    except Exception as e:
        log.warning("AWS policy change attempt failed: %s", e)
        return False


# ---------------- summary write ----------------
def write_summary(root: Path, out_file: Path):
    summary: Dict[str, Any] = {"total_files": 0, "errors": []}
    for p in root.rglob("*"):
        if p.is_file():
            summary["total_files"] += 1
            try:
                txt = p.read_text(errors="ignore")
                if "AccessDenied" in txt or "access denied" in txt.lower():
                    summary["errors"].append(str(p))
            except Exception:
                pass
    ensure_dir(out_file.parent)
    out_file.write_text(json.dumps(summary, indent=2))
    log.info("Wrote summary to %s", out_file)


# ---------------- main ----------------
def main():
    p = argparse.ArgumentParser(description="Collect cloud logs; auto-configure auth from env where possible")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 or GCS bucket name")
    p.add_argument("--container", help="Azure container name")
    p.add_argument("--prefix", default="", help="Prefix to filter")
    p.add_argument("--out", required=True, help="Local output dir")
    p.add_argument("--gcp-access-token", help="GCP access token (env GCP_ACCESS_TOKEN)")
    p.add_argument("--gcp-project", help="GCP project id (env GCP_PROJECT)")
    args = p.parse_args()

    out_dir = Path(args.out)
    ensure_dir(out_dir)

    # auto-configure GCP ADC if SA JSON provided
    ensure_gcp_adc_from_env()

    try:
        if args.provider == "aws":
            bucket = args.bucket or discover_or_create_aws_bucket()
            if not bucket:
                p.error("No AWS bucket specified and none discoverable/creatable")
            log.info("Using AWS bucket: %s", bucket)
            collect_aws(bucket, args.prefix, str(out_dir))
        elif args.provider == "gcp":
            bucket = args.bucket or discover_gcp_bucket()
            if not bucket:
                p.error("No GCP bucket specified; set --bucket or GCP_LOG_BUCKET/GCP_LOG_BUCKET_DEFAULT")
            token = args.gcp_access_token or os.environ.get("GCP_ACCESS_TOKEN")
            # if token is not set but GCP_SA_KEY env used, ADC is set above
            collect_gcp(bucket, args.prefix, str(out_dir), access_token=token, project=args.gcp_project)
        elif args.provider == "azure":
            container = args.container or discover_azure_container()
            if not container:
                p.error("No Azure container specified and AZURE_LOG_CONTAINER not set")
            collect_azure(container, args.prefix, str(out_dir))
    except SystemExit:
        raise
    except Exception as e:
        log.error("Failed to collect logs: %s", e)
        log.debug(traceback.format_exc())
        sys.exit(2)

    try:
        write_summary(out_dir, Path("data/logs/summary.json"))
    except Exception as e:
        log.warning("Failed to write summary: %s", e)


if __name_ == "__main__":
    main()
