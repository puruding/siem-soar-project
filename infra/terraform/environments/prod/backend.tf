# Remote State Backend Configuration
# Production environment uses GCS for state management with locking

terraform {
  backend "gcs" {
    bucket  = "siem-soar-terraform-state-prod"
    prefix  = "terraform/state"

    # State locking via Cloud Storage
    # Enables concurrent operations protection
    enable_encryption = true

    # Labels for cost tracking
    labels = {
      environment = "production"
      managed_by  = "terraform"
      project     = "siem-soar"
    }
  }
}

# State bucket should be created manually before first apply:
#
# gcloud storage buckets create gs://siem-soar-terraform-state-prod \
#   --project=siem-soar-production \
#   --location=asia-northeast3 \
#   --uniform-bucket-level-access \
#   --versioning \
#   --labels=environment=production,project=siem-soar
#
# Enable object versioning for state history:
# gcloud storage buckets update gs://siem-soar-terraform-state-prod --versioning
#
# Set lifecycle policy to retain 30 days of old versions:
# gcloud storage buckets update gs://siem-soar-terraform-state-prod \
#   --lifecycle-file=state-bucket-lifecycle.json
