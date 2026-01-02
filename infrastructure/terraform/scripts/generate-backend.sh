#!/usr/bin/env bash
cat > backend.hcl <<EOF2
bucket = "${TF_BACKEND_BUCKET:-your-tfstate-bucket}"
key    = "sandbox/${TF_WORKSPACE:-sandbox}.tfstate"
region = "${TF_BACKEND_REGION:-us-east-1}"
EOF2
echo "backend.hcl generated."
