forensic-poison-research
------------------------

Sandbox-safe, research-oriented research framework to simulate, detect, and remediate sophisticated poisoning attacks against Retrieval-Augmented Generation (RAG) systems across single- and multi-cloud ingestion pipelines (AWS, Azure, GCP). Deterministic local embeddings and an LLM-mock are used for reproducible experiments.

Highlights
- 10 sandboxed poisoning scenarios (reversible).
- Deterministic embedding pipeline + local FAISS-like store (docs.json + manifest).
- Cryptographic signing/verification (RSA demo keys).
- Multi-signal detectors: signature integrity, embedding-hash consistency, centroid drift, n-gram rarity, temporal activation, OPA policy checks, SIEM-style event emitter.
- Remediation: quarantine, restore from signed backups, reindex, CI-gated manual approvals.
- Terraform skeletons for AWS/Azure/GCP sandbox provisioning (minimal footprint).
- Logging helpers to collect exported audit logs from clouds.

Repository layout (key files)
- README.md (this file)
- docs/: runbook, architecture, experiment plan
- src/rag/
  - data/: seed corpus generator and poison templates
  - vectorstore/: embedding, manifest signing, faiss_store
  - detectors/: signature, embedding checks, drift, ngram, temporal, SIEM emitter, OPA rules
  - experiments/: 10 scenario scripts + runner
  - remediation/: quarantiner, restore, reindex
  - core/: llm_mock, prompt_guard
  - tests/: unit tests
- tools/
  - keygen_demo.py
  - analyze_embeddings.py
  - collect_cloud_logs.py (helper to download/export cloud audit logs)
- infrastructure/terraform/: provider skeletons for AWS/Azure/GCP
- .github/workflows/: CI, experiments-run, remediation

Goals and objectives
- Reproducibly simulate poisoning scenarios and evaluate detector coverage and remediation effectiveness.
- Validate cryptographic integrity of content and manifests.
- Collect and normalize audit logs from AWS, Azure, and GCP for cross-cloud forensic correlation.
- Provide safe CI workflows that require manual confirmation before running experiments in cloud sandboxes.

Quick local setup (macOS / VS Code terminal)
1. Clone repo and open in VS Code.
2. Generate demo RSA keys:
   - python3 tools/keygen_demo.py
   - export RAG_RSA_PRIV=keys_demo/rsa_priv.pem
   - export RAG_RSA_PUB=keys_demo/rsa_pub.pem
3. Produce corpus:
   - python3 src/rag/data/seed_generator.py
4. Build index:
   - python3 -c "import json; docs=[_import_('json').loads(l) for l in open('src/rag/data/corpus/corpus.jsonl')]; from src.rag.vectorstore.faiss_store import FaissStore; FaissStore('data/faiss_index').build(docs)"
5. Run scenario(s):
   - python3 src/rag/experiments/runner.py --scenarios all --count 5
6. Inspect detectors and remediation:
   - python3 -c "from src.rag.detectors.integrity import rsa_verify_token; print(rsa_verify_token('<token_hex>', {'id':'...','content':'...'}) )"
   - python3 -c "from src.rag.remediation.quarantiner import quarantine; print(quarantine('<doc-id>'))"

Detailed step-by-step experiment run
1. Prepare keys and baseline:
   - tools/keygen_demo.py
   - export RAG_RSA_PRIV and RAG_RSA_PUB in your shell (or CI secrets).
2. Seed corpus + baseline artifacts:
   - src/rag/data/seed_generator.py -> src/rag/data/corpus/corpus.jsonl
   - Build baseline index (FaissStore). This writes data/faiss_index/docs.json and manifest.json.
   - Compute and save baseline centroid (detectors.drift.compute_centroid and save_centroid).
   - Compute n-gram baseline (detectors.ngram_detector.compute_ngrams) and save under data/backups.
   - Create local backup: infrastructure/terraform/scripts/create-backup.sh
3. Run poisoning scenarios:
   - python3 src/rag/experiments/runner.py --scenarios all --count 5
   - Each scenario mutates data/faiss_index/docs.json to emulate attacks.
4. Run detection pipeline for query results:
   - For each doc returned by FaissStore.search():
     - Verify signature (detectors.integrity.rsa_verify_token)
     - Recompute embedding and check embedding hash (detectors.embedding_checks.check_embedding_consistency)
     - Check temporal activation (detectors.temporal.is_activated)
     - N-gram rarity (detectors.ngram_detector.is_rare)
     - Drift (detectors.drift.drift_score vs baseline)
     - OPA policies (policy.rego) evaluation
     - Emit SIEM events (detectors.siem.emit)
5. Remediation:
   - Quarantine: src/rag/remediation/quarantiner.quarantine(doc_id)
   - Restore and reindex: src/rag/remediation/restore.restore_local()
6. Post-remediation validation:
   - Verify manifest signature and each doc signature; run tests and sample queries.

Pseudocode (core flows)
- Ingest & index
  - docs = load_corpus()
  - vecs = embed_texts([d.content])
  - for each doc i:
    - doc.meta.embedding_hash = sha256(vecs[i].tobytes())
    - doc.meta.signed_token = sign({id, sha256(content)})
  - write docs.json
  - write signed manifest (doc_id -> embedding_hash)
  - build faiss index from vecs
- Query + guard + LLM-mock
  - hits = FaissStore.search(q)
  - ok, reasons = prompt_guard.guard(q, hits)
  - if not ok: emit SIEM and block
  - resp = llm_mock.deterministic_response(q, hits)
- Detection per doc
  - if not rsa_verify_token(doc.meta.signed_token, doc): emit SIEM, quarantine
  - vec = embed_texts([doc.content])[0]
  - ok, reason = check_embedding_consistency(doc, vec)
  - if not ok: emit SIEM, quarantine
  - if ngram_detector.is_rare(doc.content): mark for review
  - if drift_score > threshold: alert
  - if OPA policy denies: alert
- Remediation
  - require manual approval
  - restore backups, reindex, and re-verify

Per-scenario expected results (summary)
- label_inversion: metadata label changed; OPA denies or metadata checks flag; signatures may still validate if content unchanged.
- context_fragment_injection: novel trigger strings; n-gram rarity and prompt_guard detect; SIEM event.
- embedding_attractor: embedding drift/cluster anomalies; embedding-hash mismatches if content mutated.
- provenance_spoofing: conflicting canonical_source; OPA denies and provenance checks flag mismatch.
- shadow_token_injection: metadata contains secrets; secret scanner flags and SIEM high-severity alert.
- popularity_pumping: abnormal popularity metrics/time-series anomalies flagged.
- stale_signature_replay: content changed but token unchanged → signature verification fails.
- invisible_unicode_backdoor: zero-width characters exist; canonicalization reveals backdoor.
- delayed_activation: initially benign; detection triggers after activation timestamp.
- cross_source_inconsistency: conflicting source metadata across clouds → forensic alert.

Cloud logging and forensic guidance (detailed)
- All clouds: ensure docs preserve doc.id and signature token in object metadata on upload so logs include correlatable fields; enable export of logs to a storage bucket/container for offline analysis.

A. AWS — enable and collect
- Enable: CloudTrail (management + S3 data events), S3 server access logging, S3 object versioning.
- Key log fields: eventTime, eventName (PutObject), userIdentity.arn, sourceIPAddress, requestParameters.bucketName/objectKey, s3.requestID, s3.versionId, s3.etag.
- Forensics to collect: S3 object metadata (x-amz-meta-*), ETag/versionId, CloudTrail event JSON, S3 server access logs.
- Key validations: verify object checksums (ETag) vs local content digest (note: ETag nuances for multipart), manifest signature correctness, doc signature verification.
- Weaknesses to watch: public/unrestricted buckets, missing logging or versioning, overly-broad IAM policies.

B. Azure — enable and collect
- Enable:
  - Activity Log (control-plane) export
  - Diagnostic settings for Storage Account (Blob service) with Read/Write/Delete -> send to storage or Log Analytics
  - Azure AD sign-in and audit logs export (for identity correlation)
  - Blob versioning / soft-delete
- Key log fields: time, operationName (PutBlob, PutBlockList), callerIpAddress, identity/principalId, requestUri, statusCode, blobSize, contentMD5 (if present), requestHeaders (metadata).
- Forensics to collect: Blob metadata (x-ms-meta-*), blob properties, version snapshots, diagnostic JSONs, AD logs.
- Key validations: compare content MD5/CRC to locally computed hash (use canonicalization rules), verify manifest signature from blob, ensure diagnostic export exists.
- Weaknesses to watch: broad SAS tokens, diagnostic settings disabled, missing blob versioning.

C. GCP — enable and collect
- Enable:
  - Cloud Audit Logs: Admin Activity (default) and Data Access (for object-level) for Cloud Storage
  - GCS object versioning
  - Cloud Logging sinks to export logs to GCS/BigQuery
- Key log fields: protoPayload.methodName (storage.objects.insert), authenticationInfo.principalEmail, requestMetadata.callerIp, resourceName (bucket/object), serviceData with md5Hash/base64 & crc32c.
- Forensics to collect: object metadata/generation, audit log JSONs, Cloud Asset snapshots (IAM).
- Key validations: compare md5Hash/crc32c/generation vs local content (note base64 MD5 != SHA256), verify manifest signature stored in GCS.
- Weaknesses to watch: public buckets, disabled Data Access logs, overly-broad IAM bindings.

Cross-cloud normalization & correlation
- Normalize fields: timestamp (UTC), doc_id (object metadata), action (upload/insert), object_version/generation, principal (ARN/email/objectId), src_ip, ETag/md5/crc/hash.
- Correlate same doc.id across clouds to detect distributed ingestion/replay.
- Correlation detections:
  - simultaneous writes across clouds for same doc.id => orchestration indicator
  - object hash != manifest mapping => integrity violation
  - multiple principals writing same doc.id within timeframe => suspicious

Log collection helper
- tools/collect_cloud_logs.py: helper to download exported logs from S3/GCS/Azure storage containers (requires credentials and corresponding client libraries). Use it after configuring log export sinks in each cloud.
- Example usage:
  - AWS: python3 tools/collect_cloud_logs.py --provider aws --bucket my-log-bucket --prefix exports/ --out data/logs/aws
  - Azure: set AZURE_STORAGE_CONNECTION_STRING and run python3 tools/collect_cloud_logs.py --provider azure --container mylogs --prefix exports/ --out data/logs/azure
  - GCP: ensure GOOGLE_APPLICATION_CREDENTIALS and run python3 tools/collect_cloud_logs.py --provider gcp --bucket my-gcs-logs --prefix exports/ --out data/logs/gcp

Cryptographic model and validations
- Keys: demo RSA-2048 keys generated with tools/keygen_demo.py. In production use KMS/HSM.
- Document signing: payload = json({id, sha256(content)}); signature = RSA_PRIV.sign(payload).
- Manifest signing: manifest mapping doc_id -> embedding_hash is serialized and signed as a single payload.
- Runtime verification:
  - rsa_verify_token(token_hex, doc) recomputes sha256(content) and verifies signature with public key.
  - verify_manifest() verifies manifest signature via public key.
- Important canonicalization rules:
  - Apply deterministic canonicalization (normalize unicode, remove zero-width characters optionally, trim whitespace) when computing content hash and embedding so verifications are consistent.
- Tests:
  - Unit tests in src/rag/tests assert signing and verification behaviors.

Expected vulnerabilities (simulated)
- Stale signature replay: old signature remains after content mutation → signature verification fails.
- Metadata-only poisoning: label/popularity changes may evade content-only checks; OPA and provenance checks help detect.
- Embedding attractors: crafted content that shifts embedding distribution; detect with centroid drift and cluster anomalies.
- Invisible backdoors: zero-width or unicode tricks; require canonicalization before hashing/embedding.
- Shadow tokens in metadata: secret scanning is required.
- Cross-cloud inconsistencies: differing canonical_source across cloud copies indicate ingestion split-compromise.

SIEM / event model
- detectors.siem.emit(event) writes to data/backups/siem_events.json (simple local SIEM store for experiments).
- Recommended SIEM entries include: event_time, scenario, doc_id, detector_name, severity, observed_value, raw_log_snippet.

CI, credentials, and security guidance
- Never commit secrets to repo.
- Store cloud credentials and keys as GitHub Actions secrets:
  - AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
  - Azure: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
  - GCP: GCP_SA_KEY (service account JSON), GCP_PROJECT, GCP_REGION
  - RAG_RSA_PUB (public key) — prefer public key only for verification in CI; avoid storing private key unless necessary and only as protected secrets.
- In Actions workflows reference via: ${{ secrets.AWS_ACCESS_KEY_ID }}, etc.
- Prefer OIDC / short-lived tokens where possible and least-privilege principals.

How to add secrets to GitHub (high level)
1. Repo → Settings → Secrets and variables → Actions → New repository secret.
2. Add each required secret (name/value). For GCP SA, paste the JSON string as value.
3. In workflow jobs, map secrets to environment variables and configure cloud CLIs (aws cli, gcloud, azure/login) in job steps.

Files to add / update (code changes for logging)
- tools/collect_cloud_logs.py (helper - included in repo)
- docs/LOGGING_AND_FORENSICS.md (detailed cloud export examples and commands)
- .github/workflows/experiments-run.yml: add steps to configure cloud credentials from secrets (see existing workflow and add env var mapping).

Testing and validation checklist
- Manifest signature verifies: run src/rag/vectorstore/manifest.verify_manifest()
- Per-doc signature verifies: detectors.integrity.rsa_verify_token for a sample doc
- Embedding hash matches manifest for a sample doc
- Baseline centroid computed and saved
- Run one scenario and inspect data/backups/siem_events.json for emitted events
- Export cloud logs (via configured sinks) and use tools/collect_cloud_logs.py to fetch them; run normalization and correlation scripts (optional extension)

Safety & ethics
- All experiments are synthetic and sandbox-only by default. Do not run attacks against production systems or real user data. Use isolated test accounts and minimal, auditable privileges for cloud experiments.
