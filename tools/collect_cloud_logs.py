#!/usr/bin/env python3
"""
Collect cloud logs, attempt to fix/upgrade bucket/container permissions from code (best-effort),
download logs, and run a simple parser that summarizes events.

This version enhances the permission-fixing logic:
- AWS: tries to add a bucket policy granting s3:ListBucket and s3:GetObject to specific principals:
  - current account root (if appropriate) and optionally a provided member (env AWS_GRANT_MEMBER).
  - can also add a bucket ACL Grant for a canonical user if provided (AWS_GRANT_CANONICAL_ID).
- GCP: attempts to modify the GCS bucket IAM policy via REST or client to grant
  roles/storage.objectCreator (writer) or roles/storage.objectViewer (reader) to a provided member
  (env GCP_GRANT_MEMBER). It will use the provided access token (env GCP_ACCESS_TOKEN or --gcp-access-token)
  to call the REST IAM API; if ADC is available, it will use the google-cloud-storage client to set IAM.
- Azure: attempts to assign the built-in role "Storage Blob Data Reader" to a provided principal
  (env AZURE_GRANT_PRINCIPAL) on the storage account using Azure RBAC (requires credentials with role assignment permissions).
  If that is not possible, it can set container access policy (if AZURE_MAKE_PUBLIC=true).

Security: these actions will only succeed if the running credentials have permission to change IAM/policies.
Use with care.
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
log = logging.getLogger("collect_cloud_logs")


def ensure_dir(path: str | Path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


# ---------------- simple parser ----------------
def parse_logs_and_summarize(root: Path, out_file: Path):
    summary: Dict[str, Any] = {"total_files": 0, "total_events": 0, "cloudtrail": 0, "gcs": 0, "azure": 0, "errors": []}
    msg_counts: Dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        summary["total_files"] += 1
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            summary["errors"].append(f"read_failed:{p}:{e}")
            continue
        for line in [l.strip() for l in text.splitlines() if l.strip()]:
            obj = None
            if line.startswith("{") or line.startswith("["):
                try:
                    obj = json.loads(line)
                except Exception:
                    obj = None
            if isinstance(obj, dict):
                summary["total_events"] += 1
                if "eventName" in obj or "eventSource" in obj:
                    summary["cloudtrail"] += 1
                    msg = obj.get("eventName", obj.get("eventSource", "cloudtrail"))
                    msg_counts[msg] = msg_counts.get(msg, 0) + 1
                elif obj.get("protoPayload") or obj.get("methodName"):
                    summary["gcs"] += 1
                    msg = obj.get("methodName", "gcs")
                    msg_counts[msg] = msg_counts.get(msg, 0) + 1
                elif obj.get("operationName") or obj.get("category"):
                    summary["azure"] += 1
                    msg = obj.get("operationName", obj.get("category", "azure"))
                    msg_counts[msg] = msg_counts.get(msg, 0) + 1
                else:
                    k = obj.get("message") or (next(iter(obj.keys()), "generic"))
                    msg_counts[k] = msg_counts.get(k, 0) + 1
            else:
                kl = line.lower()
                if "access denied" in kl or "unauthoriz" in kl:
                    summary["errors"].append(f"access_denied:{p}:{line[:200]}")
    top_msgs = sorted(msg_counts.items(), key=lambda x: -x[1])[:20]
    summary["top_messages"] = [{"message": k, "count": v} for k, v in top_msgs]
    ensure_dir(out_file.parent)
    out_file.write_text(json.dumps(summary, indent=2))
    log.info("Wrote summary to %s", out_file)
    return summary


# ---------------- AWS permission enhancements ----------------
def _attempt_fix_aws_bucket_policy(bucket: str) -> bool:
    """
    Best-effort: add a bucket policy granting s3:ListBucket and s3:GetObject to:
      - account root (arn:aws:iam::ACCOUNT:root) to help runners within same account
      - optional member from env AWS_GRANT_MEMBER (e.g., arn:aws:iam::123456789012:role/SomeRole)
    Also optionally add an ACL grant if AWS_GRANT_CANONICAL_ID provided.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError

        s3 = boto3.client("s3")
        sts = boto3.client("sts")
        caller = sts.get_caller_identity()
        account = caller.get("Account")
        if not account:
            log.warning("Could not determine AWS account; skipping policy fix")
            return False

        members = [f"arn:aws:iam::{account}:root"]
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

        # Read existing policy and merge if possible:
        try:
            existing = s3.get_bucket_policy(Bucket=bucket)
            existing_policy = json.loads(existing["Policy"])
            # naive merging: append our statements if they don't already exist (by Sid)
            sids = {s.get("Sid") for s in existing_policy.get("Statement", [])}
            for stmt in policy["Statement"]:
                if stmt["Sid"] not in sids:
                    existing_policy["Statement"].append(stmt)
            new_policy = existing_policy
        except ClientError:
            new_policy = policy

        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(new_policy))
        log.info("Applied/updated bucket policy for %s", bucket)

        # optional ACL grant via canonical id (not recommended generally)
        canonical = os.environ.get("AWS_GRANT_CANONICAL_ID")
        if canonical:
            acl = s3.get_bucket_acl(Bucket=bucket)
            grants = acl.get("Grants", [])
            grants.append({"Grantee": {"Type": "CanonicalUser", "ID": canonical}, "Permission": "READ"})
            s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Owner": acl["Owner"], "Grants": grants})
            log.info("Added ACL grant for canonical ID on %s", bucket)

        # small propagation wait
        time.sleep(1)
        return True
    except Exception as e:
        log.warning("Failed to change AWS bucket policy/ACL: %s", e)
        return False


# ---------------- GCP permission enhancements ----------------
def _gcp_add_binding_rest(bucket: str, member: str, role: str, token: str) -> bool:
    """
    Use GCS bucket IAM REST endpoints to add a binding.
    Requires token to have storage.buckets.get and storage.buckets.setIamPolicy.
    """
    import requests
    from urllib.parse import quote_plus

    try:
        get_url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/iam"
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(get_url, headers=headers, timeout=30)
        if r.status_code != 200:
            log.error("GCS get IAM failed: %s %s", r.status_code, r.text)
            return False
        policy = r.json()
        bindings = policy.get("bindings", [])
        # add member to role
        updated = False
        for b in bindings:
            if b.get("role") == role:
                if member not in b.get("members", []):
                    b["members"].append(member)
                    updated = True
                else:
                    log.info("Member %s already in role %s on bucket %s", member, role, bucket)
                    return True
        if not updated:
            bindings.append({"role": role, "members": [member]})
        policy["bindings"] = bindings
        set_url = f"https://storage.googleapis.com/storage/v1/b/{quote_plus(bucket)}/iam"
        sr = requests.put(set_url, headers={**headers, "Content-Type": "application/json"}, json=policy, timeout=30)
        if sr.status_code == 200:
            log.info("Added binding %s -> %s on bucket %s via REST", member, role, bucket)
            return True
        else:
            log.error("Failed to set IAM: %s %s", sr.status_code, sr.text)
            return False
    except Exception as e:
        log.warning("GCP REST IAM change failed: %s", e)
        return False


def _gcp_add_binding_client(bucket: str, member: str, role: str, project: Optional[str] = None) -> bool:
    """
    Use google-cloud-storage client to set IAM binding (ADC/service account required).
    """
    try:
        from google.cloud import storage

        client = storage.Client(project=project)
        b = client.get_bucket(bucket)
        policy = b.get_iam_policy(requested_policy_version=3)
        if role not in policy:
            policy[role] = {member}
        else:
            if member in policy[role]:
                log.info("Member %s already in %s via client", member, role)
                return True
            policy[role].add(member)
        b.set_iam_policy(policy)
        log.info("Added binding %s -> %s on bucket %s via client", member, role, bucket)
        return True
    except Exception as e:
        log.warning("GCP client IAM change failed: %s", e)
        return False


# ---------------- Azure permission enhancements ----------------
def _attempt_azure_role_assignment(storage_account_name: str, principal_id: str, subscription_id: Optional[str] = None) -> bool:
    """
    Try to assign 'Storage Blob Data Reader' role to principal_id on the storage account scope.
    Uses azure-identity and azure-mgmt-authorization packages; requires credentials with role assignment permissions.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.storage import StorageManagementClient
        import uuid

        cred = DefaultAzureCredential()
        # determine subscription id if not provided (attempt from env)
        subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not subscription_id:
            log.warning("AZURE_SUBSCRIPTION_ID not provided; cannot perform role assignment")
            return False

        storage_client = StorageManagementClient(cred, subscription_id)
        # find resource group and account resource id by listing accounts
        accounts = storage_client.storage_accounts.list()
        target = None
        for acc in accounts:
            if acc.name == storage_account_name:
                target = acc
                break
        if not target:
            log.warning("Storage account %s not found in subscription %s", storage_account_name, subscription_id)
            return False

        # construct scope
        scope = f"/subscriptions/{subscription_id}/resourceGroups/{target.id.split('/')[4]}/providers/Microsoft.Storage/storageAccounts/{storage_account_name}"
        auth_client = AuthorizationManagementClient(cred, subscription_id)
        role_definitions = list(auth_client.role_definitions.list(scope, filter="roleName eq 'Storage Blob Data Reader'"))
        if not role_definitions:
            log.warning("Role definition Storage Blob Data Reader not found")
            return False
        role_def = role_definitions[0]
        # create role assignment
        assignment_name = str(uuid.uuid4())
        auth_client.role_assignments.create(scope, assignment_name, {"principalId": principal_id, "roleDefinitionId": role_def.id})
        log.info("Assigned Storage Blob Data Reader to %s on %s", principal_id, storage_account_name)
        return True
    except Exception as e:
        log.warning("Azure role assignment attempt failed: %s", e)
        return False


# ---------------- collectors (download after attempted fixes) ----------------
def collect_aws(bucket: str, prefix: str, out_dir: str):
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    ensure_dir(out_dir)

    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        log.warning("Cannot access bucket %s: %s. Attempting policy fix.", bucket, e)
        ok = _attempt_fix_aws_bucket_policy(bucket)
        if not ok:
            raise

    paginator = s3.get_paginator("list_objects_v2")
    downloaded = 0
    try:
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix or "", PaginationConfig={"PageSize": 1000}):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                target = os.path.join(out_dir, key)
                ensure_dir(os.path.dirname(target) or out_dir)
                try:
                    log.info("Downloading s3://%s/%s -> %s", bucket, key, target)
                    s3.download_file(bucket, key, target)
                    downloaded += 1
                except ClientError as de:
                    log.error("Failed to download %s: %s", key, de)
    except ClientError as e:
        log.error("Listing objects failed: %s", e)
        raise
    log.info("AWS: downloaded %d objects", downloaded)


def collect_gcp(bucket: str, prefix: str, out_dir: str, access_token: Optional[str] = None, project: Optional[str] = None):
    import requests

    token = access_token or os.environ.get("GCP_ACCESS_TOKEN")
    ensure_dir(out_dir)

    if token:
        # try listing
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o"
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params={"prefix": prefix} if prefix else {}, timeout=30)
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            log.info("GCP REST: found %d objects", len(items))
            downloaded = 0
            for it in items:
                name = it.get("name")
                if not name:
                    continue
                qname = requests.utils.quote(name, safe="")
                dl = requests.get(f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{qname}?alt=media", headers={"Authorization": f"Bearer {token}"}, stream=True, timeout=120)
                if dl.status_code == 200:
                    target = os.path.join(out_dir, name)
                    ensure_dir(os.path.dirname(target) or out_dir)
                    with open(target, "wb") as fh:
                        for ch in dl.iter_content(8192):
                            if ch:
                                fh.write(ch)
                    downloaded += 1
                    log.info("Downloaded gs://%s/%s -> %s", bucket, name, target)
                else:
                    log.warning("Failed to download %s: %s", name, dl.status_code)
            log.info("GCP: downloaded %d", downloaded)
            return
        elif r.status_code == 401:
            log.warning("GCP REST returned 401; attempting to add binding if GCP_GRANT_MEMBER present")
            member = os.environ.get("GCP_GRANT_MEMBER")
            if member:
                # attempt to add writer role first (objectCreator) for sink writer identities, else viewer for reads
                # preference: roles/storage.objectCreator (allow writes) then roles/storage.objectViewer
                added = _gcp_add_binding_rest(bucket, member, "roles/storage.objectCreator", token)
                if not added:
                    added = _gcp_add_binding_rest(bucket, member, "roles/storage.objectViewer", token)
                if added:
                    log.info("Added binding via REST; retrying listing")
                    return collect_gcp(bucket, prefix, out_dir, access_token=token, project=project)
        else:
            log.warning("GCP REST returned %s: %s", r.status_code, r.text)

    # ADC/client fallback: try to add binding via client if GCP_GRANT_MEMBER present
    try:
        from google.cloud import storage

        client = storage.Client(project=project)
        b = client.get_bucket(bucket)
    except Exception as e:
        log.warning("GCP ADC client unavailable or cannot access bucket: %s", e)
        # try to add binding via client if possible
        member = os.environ.get("GCP_GRANT_MEMBER")
        if member:
            ok = _gcp_add_binding_client(bucket, member, "roles/storage.objectCreator", project=project)
            if ok:
                log.info("Added binding via client; retrying using ADC")
                try:
                    from google.cloud import storage as storage2
                    client2 = storage2.Client(project=project)
                    blobs = client2.list_blobs(bucket, prefix=prefix or None)
                    downloaded = 0
                    for blob in blobs:
                        target = os.path.join(out_dir, blob.name)
                        ensure_dir(os.path.dirname(target) or out_dir)
                        blob.download_to_filename(target)
                        downloaded += 1
                    log.info("GCP: downloaded %d via client retry", downloaded)
                    return
                except Exception as e2:
                    log.warning("Retry via client failed: %s", e2)
        raise RuntimeError("GCP download failed: no working auth and no successful binding change") from e

    # if we have bucket client, list and download
    downloaded = 0
    try:
        blobs = client.list_blobs(bucket, prefix=prefix or None)
        for blob in blobs:
            target = os.path.join(out_dir, blob.name)
            ensure_dir(os.path.dirname(target) or out_dir)
            try:
                blob.download_to_filename(target)
                downloaded += 1
                log.info("Downloaded gs://%s/%s -> %s", bucket, blob.name, target)
            except Exception as de:
                log.error("Failed to download blob %s: %s", blob.name, de)
    except Exception as e:
        log.error("Listing blobs failed: %s", e)
        raise
    log.info("GCP: downloaded %d objects", downloaded)


def collect_azure(container: str, prefix: str, out_dir: str):
    from azure.storage.blob import ContainerClient
    ensure_dir(out_dir)
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not conn_str:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING required for Azure downloads")
    client = ContainerClient.from_connection_string(conn_str, container_name=container)
    try:
        downloaded = 0
        for blob in client.list_blobs(name_starts_with=prefix or None):
            target = os.path.join(out_dir, blob.name)
            ensure_dir(os.path.dirname(target) or out_dir)
            with open(target, "wb") as fh:
                fh.write(client.download_blob(blob.name).readall())
            downloaded += 1
            log.info("Downloaded azure://%s/%s -> %s", container, blob.name, target)
        log.info("AZURE: downloaded %d objects", downloaded)
        return
    except Exception as e:
        log.warning("Azure list/download failed: %s", e)
        # attempt role assignment if env set
        principal = os.environ.get("AZURE_GRANT_PRINCIPAL")  # objectId of principal to grant
        storage_account = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
        if principal and storage_account:
            ok = _attempt_azure_role_assignment(storage_account, principal)
            if ok:
                log.info("Retrying Azure downloads after role assignment")
                return collect_azure(container, prefix, out_dir)
        # optional public container toggle
        if os.environ.get("AZURE_MAKE_PUBLIC", "false").lower() == "true":
            try:
                client.set_container_access_policy(public_access="container")
                log.info("Set container to public; retrying")
                return collect_azure(container, prefix, out_dir)
            except Exception as e2:
                log.warning("Failed to set public access: %s", e2)
        raise


# ---------------- main orchestration ----------------
def main():
    p = argparse.ArgumentParser(description="Collect cloud logs, enhance permissions, download and parse")
    p.add_argument("--provider", choices=["aws", "gcp", "azure"], required=True)
    p.add_argument("--bucket", help="S3 or GCS bucket name")
    p.add_argument("--container", help="Azure container name")
    p.add_argument("--prefix", default="", help="Prefix to filter")
    p.add_argument("--out", required=True, help="Local output directory")
    p.add_argument("--gcp-access-token", help="GCP access token (env GCP_ACCESS_TOKEN)")
    p.add_argument("--gcp-project", help="GCP project id (env GCP_PROJECT)")
    args = p.parse_args()

    out_dir = Path(args.out)
    ensure_dir(out_dir)

    try:
        if args.provider == "aws":
            bucket = args.bucket or os.environ.get("AWS_LOG_BUCKET") or _discover_aws_bucket()
            if not bucket:
                p.error("AWS bucket not specified and none discovered")
            log.info("Ensuring permissions on AWS bucket %s", bucket)
            _attempt_fix_aws_bucket_policy(bucket)
            collect_aws(bucket, args.prefix, str(out_dir))
        elif args.provider == "gcp":
            bucket = args.bucket or os.environ.get("GCP_LOG_BUCKET")
            if not bucket:
                p.error("GCP bucket not specified")
            token = args.gcp_access_token or os.environ.get("GCP_ACCESS_TOKEN")
            member = os.environ.get("GCP_GRANT_MEMBER")
            if token and member:
                # try to add write binding for sink writer identities or provided member
                added = _gcp_add_binding_rest(bucket, member, "roles/storage.objectCreator", token)
                if not added:
                    _gcp_add_binding_rest(bucket, member, "roles/storage.objectViewer", token)
            # attempt client-side binding if ADC and member present
            if member:
                _gcp_add_binding_client(bucket, member, "roles/storage.objectCreator", project=args.gcp_project)
            collect_gcp(bucket, args.prefix, str(out_dir), access_token=token, project=args.gcp_project)
        elif args.provider == "azure":
            container = args.container or os.environ.get("AZURE_LOG_CONTAINER")
            if not container:
                p.error("Azure container not specified")
            # attempt role assignment if AZURE_GRANT_PRINCIPAL and AZURE_STORAGE_ACCOUNT_NAME provided
            principal = os.environ.get("AZURE_GRANT_PRINCIPAL")
            storage_account = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
            if principal and storage_account:
                _attempt_azure_role_assignment(storage_account, principal)
            collect_azure(container, args.prefix, str(out_dir))
    except SystemExit:
        raise
    except Exception as e:
        log.error("Failed to collect logs: %s", e)
        log.debug(traceback.format_exc())
        sys.exit(2)

    # parse and write summary
    try:
        summary = parse_logs_and_summarize(out_dir, Path("data/logs/summary.json"))
        log.info("Summary: %s", json.dumps(summary, indent=2)[:1000])
    except Exception as e:
        log.error("Parsing failed: %s", e)
        log.debug(traceback.format_exc())


# helper for AWS discovery used in main
def _discover_aws_bucket() -> Optional[str]:
    for name in ("AWS_LOG_BUCKET", "TF_VAR_tf_state_bucket", "AWS_LOG_BUCKET_DEFAULT"):
        v = os.environ.get(name)
        if v:
            return v
    try:
        import boto3
        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        prefix = os.environ.get("AWS_LOG_BUCKET_DEFAULT", "rag-forensic-logs")
        for b in resp.get("Buckets", []):
            nm = b.get("Name", "")
            if nm.startswith(prefix):
                return nm
    except Exception:
        return None


if __name__ == "__main__":
    main()
