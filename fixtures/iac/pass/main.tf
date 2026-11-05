terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

provider "google" {
  project = var.project
}

variable "project" {
  type = string
}

resource "google_storage_bucket" "logs" {
  name     = "acme-gate-logs"
  location = "EU"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  logging {
    log_bucket = "acme-audit-logs"
  }

  retention_policy {
    retention_period = 86400
  }
}

module "storage" {
  source = "./modules/storage"
}
