# GCP Network Module Variables

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

variable "network_name" {
  description = "VPC Network name"
  type        = string
}

variable "subnet_configs" {
  description = "Subnet configurations"
  type = map(object({
    ip_cidr_range    = string
    region           = string
    secondary_ranges = optional(map(string), {})
  }))
}
