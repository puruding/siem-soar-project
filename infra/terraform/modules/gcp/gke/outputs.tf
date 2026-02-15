# GCP GKE Module Outputs

output "cluster_name" {
  description = "GKE Cluster name"
  value       = google_container_cluster.primary.name
}

output "cluster_id" {
  description = "GKE Cluster ID"
  value       = google_container_cluster.primary.id
}

output "endpoint" {
  description = "GKE Cluster API endpoint"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "ca_certificate" {
  description = "GKE Cluster CA certificate"
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "location" {
  description = "GKE Cluster location"
  value       = google_container_cluster.primary.location
}

output "node_pools" {
  description = "Node pool names"
  value       = [for np in google_container_node_pool.pools : np.name]
}

output "service_account" {
  description = "GKE Node Service Account email"
  value       = google_service_account.gke_sa.email
}

output "workload_identity_pool" {
  description = "Workload Identity Pool"
  value       = "${var.project_id}.svc.id.goog"
}
