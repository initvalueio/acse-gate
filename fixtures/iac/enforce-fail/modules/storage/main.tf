resource "google_storage_bucket" "data" {
  name     = "acme-gate-data"
  location = "EU"
  project  = "acme-prod-data"

  uniform_bucket_level_access = false
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
