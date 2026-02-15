# SIEM-SOAR Platform Terraform Variables
# Configurable parameters for infrastructure provisioning

# =============================================================================
# General Variables
# =============================================================================
variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "cloud_provider" {
  description = "Primary cloud provider (gcp or aws)"
  type        = string
  default     = "gcp"
  validation {
    condition     = contains(["gcp", "aws"], var.cloud_provider)
    error_message = "Cloud provider must be one of: gcp, aws."
  }
}

# =============================================================================
# GCP Variables
# =============================================================================
variable "gcp_project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP Region for resources"
  type        = string
  default     = "asia-northeast3"
}

variable "gcp_zones" {
  description = "GCP Zones for GKE cluster"
  type        = list(string)
  default     = ["asia-northeast3-a", "asia-northeast3-b", "asia-northeast3-c"]
}

# =============================================================================
# AWS Variables
# =============================================================================
variable "aws_region" {
  description = "AWS Region for resources"
  type        = string
  default     = "ap-northeast-2"
}

variable "aws_azs" {
  description = "AWS Availability Zones"
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"]
}

# =============================================================================
# Node Pool - Compute (Go Services, Web)
# =============================================================================
variable "compute_machine_type" {
  description = "GCP machine type for compute nodes"
  type        = string
  default     = "n2-standard-8"
}

variable "aws_compute_instance_type" {
  description = "AWS instance type for compute nodes"
  type        = string
  default     = "m6i.2xlarge"
}

variable "compute_min_nodes" {
  description = "Minimum number of compute nodes"
  type        = number
  default     = 3
}

variable "compute_max_nodes" {
  description = "Maximum number of compute nodes"
  type        = number
  default     = 20
}

# =============================================================================
# Node Pool - Data (ClickHouse, Kafka, Redis)
# =============================================================================
variable "data_machine_type" {
  description = "GCP machine type for data nodes"
  type        = string
  default     = "n2-highmem-16"
}

variable "aws_data_instance_type" {
  description = "AWS instance type for data nodes"
  type        = string
  default     = "r6i.4xlarge"
}

variable "data_min_nodes" {
  description = "Minimum number of data nodes"
  type        = number
  default     = 3
}

variable "data_max_nodes" {
  description = "Maximum number of data nodes"
  type        = number
  default     = 10
}

# =============================================================================
# Node Pool - AI (ML/LLM Workloads)
# =============================================================================
variable "ai_machine_type" {
  description = "GCP machine type for AI nodes"
  type        = string
  default     = "n1-highmem-16"
}

variable "aws_ai_instance_type" {
  description = "AWS instance type for AI nodes"
  type        = string
  default     = "g4dn.4xlarge"
}

variable "ai_min_nodes" {
  description = "Minimum number of AI nodes"
  type        = number
  default     = 1
}

variable "ai_max_nodes" {
  description = "Maximum number of AI nodes"
  type        = number
  default     = 8
}

# =============================================================================
# Kubernetes Configuration
# =============================================================================
variable "kubernetes_version" {
  description = "Kubernetes version for the cluster"
  type        = string
  default     = "1.29"
}

variable "enable_private_cluster" {
  description = "Enable private cluster with no public IPs on nodes"
  type        = bool
  default     = true
}

variable "master_ipv4_cidr_block" {
  description = "CIDR block for GKE master nodes"
  type        = string
  default     = "172.16.0.0/28"
}

# =============================================================================
# Storage Configuration
# =============================================================================
variable "clickhouse_storage_size_gb" {
  description = "Storage size for ClickHouse in GB"
  type        = number
  default     = 1000
}

variable "kafka_storage_size_gb" {
  description = "Storage size for Kafka in GB"
  type        = number
  default     = 500
}

variable "postgres_storage_size_gb" {
  description = "Storage size for PostgreSQL in GB"
  type        = number
  default     = 100
}

# =============================================================================
# Networking
# =============================================================================
variable "enable_nat_gateway" {
  description = "Enable NAT gateway for private subnets"
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the cluster"
  type        = list(string)
  default     = []
}

# =============================================================================
# Tags/Labels
# =============================================================================
variable "additional_tags" {
  description = "Additional tags/labels to apply to resources"
  type        = map(string)
  default     = {}
}
