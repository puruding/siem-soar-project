# SIEM-SOAR Platform Terraform Outputs
# Exported values for downstream consumption (CI/CD, ArgoCD, etc.)

# =============================================================================
# General Outputs
# =============================================================================
output "environment" {
  description = "Deployment environment"
  value       = var.environment
}

output "cloud_provider" {
  description = "Cloud provider used"
  value       = var.cloud_provider
}

# =============================================================================
# GCP Outputs
# =============================================================================
output "gcp_project_id" {
  description = "GCP Project ID"
  value       = var.cloud_provider == "gcp" ? var.gcp_project_id : null
}

output "gcp_region" {
  description = "GCP Region"
  value       = var.cloud_provider == "gcp" ? var.gcp_region : null
}

output "gcp_network_name" {
  description = "GCP VPC Network name"
  value       = var.cloud_provider == "gcp" ? module.gcp_network[0].network_name : null
}

output "gcp_network_id" {
  description = "GCP VPC Network ID"
  value       = var.cloud_provider == "gcp" ? module.gcp_network[0].network_id : null
}

output "gke_cluster_name" {
  description = "GKE Cluster name"
  value       = var.cloud_provider == "gcp" ? module.gcp_gke[0].cluster_name : null
}

output "gke_cluster_endpoint" {
  description = "GKE Cluster API endpoint"
  value       = var.cloud_provider == "gcp" ? module.gcp_gke[0].endpoint : null
  sensitive   = true
}

output "gke_cluster_ca_certificate" {
  description = "GKE Cluster CA certificate"
  value       = var.cloud_provider == "gcp" ? module.gcp_gke[0].ca_certificate : null
  sensitive   = true
}

# =============================================================================
# AWS Outputs
# =============================================================================
output "aws_region" {
  description = "AWS Region"
  value       = var.cloud_provider == "aws" ? var.aws_region : null
}

output "aws_vpc_id" {
  description = "AWS VPC ID"
  value       = var.cloud_provider == "aws" ? module.aws_network[0].vpc_id : null
}

output "eks_cluster_name" {
  description = "EKS Cluster name"
  value       = var.cloud_provider == "aws" ? module.aws_eks[0].cluster_name : null
}

output "eks_cluster_endpoint" {
  description = "EKS Cluster API endpoint"
  value       = var.cloud_provider == "aws" ? module.aws_eks[0].endpoint : null
  sensitive   = true
}

output "eks_cluster_ca_certificate" {
  description = "EKS Cluster CA certificate"
  value       = var.cloud_provider == "aws" ? module.aws_eks[0].ca_certificate : null
  sensitive   = true
}

# =============================================================================
# Kubernetes Outputs (Generic)
# =============================================================================
output "kubernetes_cluster_name" {
  description = "Kubernetes cluster name"
  value       = var.cloud_provider == "gcp" ? module.gcp_gke[0].cluster_name : module.aws_eks[0].cluster_name
}

output "kubernetes_endpoint" {
  description = "Kubernetes API endpoint"
  value       = var.cloud_provider == "gcp" ? module.gcp_gke[0].endpoint : module.aws_eks[0].endpoint
  sensitive   = true
}

output "kubernetes_ca_certificate" {
  description = "Kubernetes cluster CA certificate (base64 encoded)"
  value       = var.cloud_provider == "gcp" ? module.gcp_gke[0].ca_certificate : module.aws_eks[0].ca_certificate
  sensitive   = true
}

# =============================================================================
# Storage Outputs
# =============================================================================
output "storage_buckets" {
  description = "Cloud storage buckets/S3 buckets"
  value = var.cloud_provider == "gcp" ? {
    logs      = module.gcp_storage[0].bucket_names["logs"]
    backups   = module.gcp_storage[0].bucket_names["backups"]
    ml_models = module.gcp_storage[0].bucket_names["ml_models"]
  } : null
}

# =============================================================================
# Connection Strings (for configuration)
# =============================================================================
output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value = var.cloud_provider == "gcp" ? (
    "gcloud container clusters get-credentials ${module.gcp_gke[0].cluster_name} --region ${var.gcp_region} --project ${var.gcp_project_id}"
  ) : (
    "aws eks update-kubeconfig --name ${module.aws_eks[0].cluster_name} --region ${var.aws_region}"
  )
}

# =============================================================================
# ArgoCD Configuration
# =============================================================================
output "argocd_cluster_config" {
  description = "ArgoCD cluster configuration"
  value = {
    name   = "siem-soar-${var.environment}"
    server = var.cloud_provider == "gcp" ? module.gcp_gke[0].endpoint : module.aws_eks[0].endpoint
  }
  sensitive = true
}

# =============================================================================
# Node Pool Information
# =============================================================================
output "node_pools" {
  description = "Node pool configuration summary"
  value = {
    compute = {
      min_nodes = var.compute_min_nodes
      max_nodes = var.compute_max_nodes
      machine_type = var.cloud_provider == "gcp" ? var.compute_machine_type : var.aws_compute_instance_type
    }
    data = {
      min_nodes = var.data_min_nodes
      max_nodes = var.data_max_nodes
      machine_type = var.cloud_provider == "gcp" ? var.data_machine_type : var.aws_data_instance_type
    }
    ai = {
      min_nodes = var.ai_min_nodes
      max_nodes = var.ai_max_nodes
      machine_type = var.cloud_provider == "gcp" ? var.ai_machine_type : var.aws_ai_instance_type
    }
  }
}
