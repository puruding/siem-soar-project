# GCP Storage Module Variables

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

variable "buckets" {
  description = "Bucket configurations"
  type = map(object({
    name          = string
    storage_class = string
    versioning    = optional(bool, true)
    lifecycle_rules = optional(list(object({
      action_type = string
      age_days    = number
    })), [])
  }))
}

variable "service_account_email" {
  description = "Service account email for IAM binding"
  type        = string
  default     = ""
}
