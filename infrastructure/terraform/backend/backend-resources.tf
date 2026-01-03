name: Terraform Backend Setup

on:
  workflow_dispatch:
    inputs:
      action:
        description: 'Terraform action to perform'
        required: true
        type: choice
        options:
          - plan
          - apply
          - destroy
      cloud_provider:
        description: 'Cloud provider(s) to configure'
        required: true
        type: choice
        options:
          - aws
          - gcp
          - azure
          - all

env:
  TF_VERSION: '1.6.0'
  WORKING_DIR: 'infrastructure/terraform/backend'

jobs:
  terraform:
    name: 'Terraform Backend - ${{ github.event.inputs.cloud_provider }}'
    runs-on: ubuntu-latest
    
    # Use OIDC for secure authentication without long-lived credentials
    permissions:
      id-token: write
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      # ====================
      # AWS Authentication
      # ====================
      - name: Configure AWS Credentials (OIDC)
        if: github.event.inputs.cloud_provider == 'aws' || github.event.inputs.cloud_provider == 'all'
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ secrets.AWS_REGION }}
          # Alternative: Use static credentials
          # aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          # aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

      # ====================
      # GCP Authentication
      # ====================
      - name: Authenticate to Google Cloud (OIDC)
        if: github.event.inputs.cloud_provider == 'gcp' || github.event.inputs.cloud_provider == 'all'
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}
          # Alternative: Use service account key
          # credentials_json: ${{ secrets.GCP_CREDENTIALS }}

      - name: Set up Cloud SDK
        if: github.event.inputs.cloud_provider == 'gcp' || github.event.inputs.cloud_provider == 'all'
        uses: google-github-actions/setup-gcloud@v2

      # ====================
      # Azure Authentication
      # ====================
      - name: Azure Login (OIDC)
        if: github.event.inputs.cloud_provider == 'azure' || github.event.inputs.cloud_provider == 'all'
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          # Alternative: Use service principal with secret
          # creds: ${{ secrets.AZURE_CREDENTIALS }}

      # ====================
      # Terraform Setup
      # ====================
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}

      - name: Create terraform.tfvars
        working-directory: ${{ env.WORKING_DIR }}
        run: |
          cat > terraform.tfvars <<EOF
          # Cloud provider toggles
          create_aws   = ${{ github.event.inputs.cloud_provider == 'aws' || github.event.inputs.cloud_provider == 'all' }}
          create_gcp   = ${{ github.event.inputs.cloud_provider == 'gcp' || github.event.inputs.cloud_provider == 'all' }}
          create_azure = ${{ github.event.inputs.cloud_provider == 'azure' || github.event.inputs.cloud_provider == 'all' }}

          # AWS Configuration
          aws_region       = "${{ secrets.AWS_REGION }}"
          tf_state_bucket  = "${{ secrets.TF_STATE_BUCKET }}"
          tf_lock_table    = "${{ secrets.TF_LOCK_TABLE }}"

          # GCP Configuration
          gcp_project = "${{ secrets.GCP_PROJECT_ID }}"
          gcp_region  = "${{ secrets.GCP_REGION }}"
          gcs_bucket  = "${{ secrets.GCS_BUCKET }}"

          # Azure Configuration
          azure_rg_name         = "${{ secrets.AZURE_RG_NAME }}"
          azure_location        = "${{ secrets.AZURE_LOCATION }}"
          azure_storage_account = "${{ secrets.AZURE_STORAGE_ACCOUNT }}"
          azure_container_name  = "${{ secrets.AZURE_CONTAINER_NAME }}"
          EOF

      - name: Terraform Init
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform init

      - name: Terraform Format Check
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform fmt -check -recursive

      - name: Terraform Validate
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform validate

      - name: Terraform Plan
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform plan -out=tfplan
        env:
          # GCP credentials for static auth method
          GOOGLE_CREDENTIALS: ${{ secrets.GCP_CREDENTIALS }}
          # Azure credentials for static auth method
          ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Terraform Apply
        if: github.event.inputs.action == 'apply'
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform apply -auto-approve tfplan
        env:
          GOOGLE_CREDENTIALS: ${{ secrets.GCP_CREDENTIALS }}
          ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Terraform Destroy
        if: github.event.inputs.action == 'destroy'
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform destroy -auto-approve
        env:
          GOOGLE_CREDENTIALS: ${{ secrets.GCP_CREDENTIALS }}
          ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Upload Terraform Plan
        if: github.event.inputs.action == 'plan'
        uses: actions/upload-artifact@v4
        with:
          name: terraform-plan
          path: ${{ env.WORKING_DIR }}/tfplan
          retention-days: 5
