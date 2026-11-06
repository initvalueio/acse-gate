# GCP pack -- gcp-storage-retention-policy (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `retention_policy_set` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_storage_retention_policy

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.retention_policy_set == false
}

outcome := "PASS" if {
	input.retention_policy_set == true
}
