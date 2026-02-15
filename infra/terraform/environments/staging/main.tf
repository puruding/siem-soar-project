# Staging Environment Terraform Configuration
# Production-like setup for pre-release testing

terraform {
  required_version = ">= 1.7.0"

  backend "gcs" {
    bucket = "siem-soar-terraform-state"
    prefix = "terraform/state/staging"
  }
}

module "siem_soar" {
  source = "../../"

  environment    = "staging"
  cloud_provider = "gcp"

  # GCP Configuration
  gcp_project_id = var.gcp_project_id
  gcp_region     = "asia-northeast3"

  # Node Pool Sizing (Medium, production-like)
  compute_machine_type = "n2-standard-8"
  compute_min_nodes    = 3
  compute_max_nodes    = 10

  data_machine_type = "n2-highmem-16"
  data_min_nodes    = 3
  data_max_nodes    = 6

  ai_machine_type = "n1-highmem-16"
  ai_min_nodes    = 1
  ai_max_nodes    = 4

  # Storage (Production-like)
  clickhouse_storage_size_gb = 500
  kafka_storage_size_gb      = 300
  postgres_storage_size_gb   = 100

  additional_tags = {
    cost_center = "staging"
  }
}

variable "gcp_project_id" {
  description = "GCP Project ID"
  type        = string
}

output "kubernetes_cluster_name" {
  value = module.siem_soar.kubernetes_cluster_name
}

output "kubeconfig_command" {
  value = module.siem_soar.kubeconfig_command
}
