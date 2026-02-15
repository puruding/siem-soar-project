# GCP Network Module Outputs

output "network_name" {
  description = "VPC Network name"
  value       = google_compute_network.vpc.name
}

output "network_id" {
  description = "VPC Network ID"
  value       = google_compute_network.vpc.id
}

output "network_self_link" {
  description = "VPC Network self link"
  value       = google_compute_network.vpc.self_link
}

output "subnet_ids" {
  description = "Map of subnet names to IDs"
  value       = { for k, v in google_compute_subnetwork.subnets : k => v.id }
}

output "subnet_self_links" {
  description = "Map of subnet names to self links"
  value       = { for k, v in google_compute_subnetwork.subnets : k => v.self_link }
}

output "router_name" {
  description = "Cloud Router name"
  value       = google_compute_router.router.name
}

output "nat_name" {
  description = "Cloud NAT name"
  value       = google_compute_router_nat.nat.name
}
