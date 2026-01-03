#!/usr/bin/env bash
set -e
mkdir -p data/backups
cp -f data/faiss_index/docs.json data/backups/faiss_docs.json || true
cp -f data/faiss_index/manifest.json data/backups/manifest.json || true
echo "Local backups created under data/backups/"
