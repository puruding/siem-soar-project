# SIEM-SOAR Platform Terraform Configuration
# Root module that orchestrates cloud infrastructure provisioning

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "gcs" {
    # Configured per environment
    # bucket = "siem-soar-terraform-state"
    # prefix = "terraform/state"
  }
}

# =============================================================================
# Local Variables
# =============================================================================
locals {
  environment = var.environment
  project_id  = var.gcp_project_id
  region      = var.gcp_region

  common_labels = {
    project     = "siem-soar-platform"
    environment = var.environment
    managed_by  = "terraform"
  }

  # Service configurations
  go_services = [
    "gateway",
    "detection",
    "soar",
    "ti",
    "query",
    "case",
    "collector",
    "pipeline"
  ]

  python_services = [
    "ai-triage",
    "ai-copilot",
    "ai-agentic"
  ]
}

# =============================================================================
# GCP Provider Configuration
# =============================================================================
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "google-beta" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# =============================================================================
# GCP Infrastructure (Primary)
# =============================================================================
module "gcp_network" {
  source = "./modules/gcp/network"
  count  = var.cloud_provider == "gcp" ? 1 : 0

  project_id   = var.gcp_project_id
  region       = var.gcp_region
  environment  = var.environment
  network_name = "siem-soar-vpc"

  subnet_configs = {
    gke = {
      ip_cidr_range = "10.0.0.0/20"
      region        = var.gcp_region
      secondary_ranges = {
        pods     = "10.4.0.0/14"
        services = "10.8.0.0/20"
      }
    }
    data = {
      ip_cidr_range = "10.1.0.0/20"
      region        = var.gcp_region
    }
  }
}

module "gcp_gke" {
  source = "./modules/gcp/gke"
  count  = var.cloud_provider == "gcp" ? 1 : 0

  project_id   = var.gcp_project_id
  region       = var.gcp_region
  environment  = var.environment
  cluster_name = "siem-soar-${var.environment}"

  network_id    = module.gcp_network[0].network_id
  subnet_id     = module.gcp_network[0].subnet_ids["gke"]
  pods_range    = "pods"
  services_range = "services"

  node_pools = {
    compute = {
      machine_type   = var.compute_machine_type
      min_node_count = var.compute_min_nodes
      max_node_count = var.compute_max_nodes
      disk_size_gb   = 100
      disk_type      = "pd-ssd"
      labels = {
        "node-pool"     = "compute"
        "workload-type" = "stateless"
      }
    }
    data = {
      machine_type   = var.data_machine_type
      min_node_count = var.data_min_nodes
      max_node_count = var.data_max_nodes
      disk_size_gb   = 200
      disk_type      = "pd-ssd"
      local_ssd_count = 2
      labels = {
        "node-pool"     = "data"
        "workload-type" = "stateful"
      }
      taints = [{
        key    = "workload-type"
        value  = "data"
        effect = "NO_SCHEDULE"
      }]
    }
    ai = {
      machine_type   = var.ai_machine_type
      min_node_count = var.ai_min_nodes
      max_node_count = var.ai_max_nodes
      disk_size_gb   = 200
      disk_type      = "pd-ssd"
      accelerator_type  = "nvidia-tesla-t4"
      accelerator_count = 2
      labels = {
        "node-pool"     = "ai"
        "workload-type" = "ml"
        "gpu"           = "nvidia-t4"
      }
      taints = [
        {
          key    = "nvidia.com/gpu"
          value  = "present"
          effect = "NO_SCHEDULE"
        },
        {
          key    = "workload-type"
          value  = "ai"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }

  depends_on = [module.gcp_network]
}

module "gcp_storage" {
  source = "./modules/gcp/storage"
  count  = var.cloud_provider == "gcp" ? 1 : 0

  project_id  = var.gcp_project_id
  region      = var.gcp_region
  environment = var.environment

  buckets = {
    logs = {
      name          = "siem-soar-logs-${var.environment}"
      storage_class = "STANDARD"
      lifecycle_rules = [{
        action_type = "Delete"
        age_days    = 90
      }]
    }
    backups = {
      name          = "siem-soar-backups-${var.environment}"
      storage_class = "NEARLINE"
      lifecycle_rules = [{
        action_type = "Delete"
        age_days    = 365
      }]
    }
    ml_models = {
      name          = "siem-soar-ml-models-${var.environment}"
      storage_class = "STANDARD"
    }
  }
}

# =============================================================================
# AWS Infrastructure (Alternative)
# =============================================================================
provider "aws" {
  region = var.aws_region
}

module "aws_network" {
  source = "./modules/aws/network"
  count  = var.cloud_provider == "aws" ? 1 : 0

  environment = var.environment
  vpc_cidr    = "10.0.0.0/16"
  azs         = var.aws_azs

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  tags = local.common_labels
}

module "aws_eks" {
  source = "./modules/aws/eks"
  count  = var.cloud_provider == "aws" ? 1 : 0

  cluster_name = "siem-soar-${var.environment}"
  environment  = var.environment

  vpc_id          = module.aws_network[0].vpc_id
  private_subnets = module.aws_network[0].private_subnet_ids

  node_groups = {
    compute = {
      instance_types = [var.aws_compute_instance_type]
      min_size       = var.compute_min_nodes
      max_size       = var.compute_max_nodes
      desired_size   = var.compute_min_nodes
      disk_size      = 100
      labels = {
        "node-pool"     = "compute"
        "workload-type" = "stateless"
      }
    }
    data = {
      instance_types = [var.aws_data_instance_type]
      min_size       = var.data_min_nodes
      max_size       = var.data_max_nodes
      desired_size   = var.data_min_nodes
      disk_size      = 200
      labels = {
        "node-pool"     = "data"
        "workload-type" = "stateful"
      }
      taints = [{
        key    = "workload-type"
        value  = "data"
        effect = "NO_SCHEDULE"
      }]
    }
    ai = {
      instance_types = [var.aws_ai_instance_type]
      min_size       = var.ai_min_nodes
      max_size       = var.ai_max_nodes
      desired_size   = var.ai_min_nodes
      disk_size      = 200
      ami_type       = "AL2_x86_64_GPU"
      labels = {
        "node-pool"     = "ai"
        "workload-type" = "ml"
        "gpu"           = "nvidia-t4"
      }
      taints = [
        {
          key    = "nvidia.com/gpu"
          value  = "present"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }

  depends_on = [module.aws_network]
}

# =============================================================================
# Kubernetes Provider Configuration (after cluster creation)
# =============================================================================
data "google_client_config" "default" {
  count = var.cloud_provider == "gcp" ? 1 : 0
}

provider "kubernetes" {
  host  = var.cloud_provider == "gcp" ? module.gcp_gke[0].endpoint : module.aws_eks[0].endpoint
  token = var.cloud_provider == "gcp" ? data.google_client_config.default[0].access_token : null

  cluster_ca_certificate = base64decode(
    var.cloud_provider == "gcp"
      ? module.gcp_gke[0].ca_certificate
      : module.aws_eks[0].ca_certificate
  )
}

provider "helm" {
  kubernetes {
    host  = var.cloud_provider == "gcp" ? module.gcp_gke[0].endpoint : module.aws_eks[0].endpoint
    token = var.cloud_provider == "gcp" ? data.google_client_config.default[0].access_token : null

    cluster_ca_certificate = base64decode(
      var.cloud_provider == "gcp"
        ? module.gcp_gke[0].ca_certificate
        : module.aws_eks[0].ca_certificate
    )
  }
}
