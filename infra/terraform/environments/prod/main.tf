# Production Environment Terraform Configuration
# Full-scale production deployment

terraform {
  required_version = ">= 1.7.0"

  backend "gcs" {
    bucket = "siem-soar-terraform-state"
    prefix = "terraform/state/prod"
  }
}

module "siem_soar" {
  source = "../../"

  environment    = "prod"
  cloud_provider = "gcp"

  # GCP Configuration
  gcp_project_id = var.gcp_project_id
  gcp_region     = "asia-northeast3"

  # Node Pool Sizing (Full production scale)
  compute_machine_type = "n2-standard-8"
  compute_min_nodes    = 5
  compute_max_nodes    = 20

  data_machine_type = "n2-highmem-16"
  data_min_nodes    = 3
  data_max_nodes    = 10

  ai_machine_type = "n1-highmem-16"
  ai_min_nodes    = 2
  ai_max_nodes    = 8

  # Storage (Full production)
  clickhouse_storage_size_gb = 1000
  kafka_storage_size_gb      = 500
  postgres_storage_size_gb   = 100

  # Security
  enable_private_cluster = true

  additional_tags = {
    cost_center = "production"
    compliance  = "soc2"
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
