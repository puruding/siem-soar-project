# GCP Storage Module Outputs

output "bucket_names" {
  description = "Map of bucket keys to names"
  value       = { for k, v in google_storage_bucket.buckets : k => v.name }
}

output "bucket_urls" {
  description = "Map of bucket keys to URLs"
  value       = { for k, v in google_storage_bucket.buckets : k => v.url }
}

output "bucket_self_links" {
  description = "Map of bucket keys to self links"
  value       = { for k, v in google_storage_bucket.buckets : k => v.self_link }
}
