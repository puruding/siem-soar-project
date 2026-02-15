# GCP GKE Module Variables

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "cluster_name" {
  description = "GKE Cluster name"
  type        = string
}

variable "network_id" {
  description = "VPC Network ID"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for GKE nodes"
  type        = string
}

variable "pods_range" {
  description = "Name of the secondary range for pods"
  type        = string
}

variable "services_range" {
  description = "Name of the secondary range for services"
  type        = string
}

variable "master_ipv4_cidr_block" {
  description = "CIDR block for GKE master nodes"
  type        = string
  default     = "172.16.0.0/28"
}

variable "authorized_networks" {
  description = "List of authorized networks for master access"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = [
    {
      cidr_block   = "0.0.0.0/0"
      display_name = "All"
    }
  ]
}

variable "node_pools" {
  description = "Node pool configurations"
  type = map(object({
    machine_type      = string
    min_node_count    = number
    max_node_count    = number
    disk_size_gb      = number
    disk_type         = string
    local_ssd_count   = optional(number, 0)
    accelerator_type  = optional(string)
    accelerator_count = optional(number, 0)
    labels            = map(string)
    taints            = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))
}
