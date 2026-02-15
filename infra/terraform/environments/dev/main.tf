# Development Environment Terraform Configuration
# Minimal resources for development and testing

terraform {
  required_version = ">= 1.7.0"

  backend "gcs" {
    bucket = "siem-soar-terraform-state"
    prefix = "terraform/state/dev"
  }
}

module "siem_soar" {
  source = "../../"

  environment    = "dev"
  cloud_provider = "gcp"

  # GCP Configuration
  gcp_project_id = var.gcp_project_id
  gcp_region     = "asia-northeast3"

  # Node Pool Sizing (Minimal for dev)
  compute_machine_type = "n2-standard-4"
  compute_min_nodes    = 2
  compute_max_nodes    = 5

  data_machine_type = "n2-highmem-8"
  data_min_nodes    = 2
  data_max_nodes    = 4

  ai_machine_type = "n1-highmem-8"
  ai_min_nodes    = 0
  ai_max_nodes    = 2

  # Storage (Smaller for dev)
  clickhouse_storage_size_gb = 200
  kafka_storage_size_gb      = 100
  postgres_storage_size_gb   = 50

  additional_tags = {
    cost_center = "development"
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
