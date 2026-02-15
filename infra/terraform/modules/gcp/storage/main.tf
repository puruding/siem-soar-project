# GCP Storage Module
# Creates GCS buckets for logs, backups, and ML models

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# =============================================================================
# GCS Buckets
# =============================================================================
resource "google_storage_bucket" "buckets" {
  for_each = var.buckets

  name          = each.value.name
  project       = var.project_id
  location      = var.region
  storage_class = each.value.storage_class
  force_destroy = var.environment != "prod"

  uniform_bucket_level_access = true

  versioning {
    enabled = lookup(each.value, "versioning", true)
  }

  dynamic "lifecycle_rule" {
    for_each = lookup(each.value, "lifecycle_rules", [])
    content {
      action {
        type = lifecycle_rule.value.action_type
      }
      condition {
        age = lifecycle_rule.value.age_days
      }
    }
  }

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    project     = "siem-soar-platform"
  }
}

# =============================================================================
# IAM Bindings
# =============================================================================
resource "google_storage_bucket_iam_member" "bucket_admin" {
  for_each = var.buckets

  bucket = google_storage_bucket.buckets[each.key].name
  role   = "roles/storage.admin"
  member = "serviceAccount:${var.service_account_email}"
}
