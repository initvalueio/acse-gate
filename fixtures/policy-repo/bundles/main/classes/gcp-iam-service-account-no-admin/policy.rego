# GCP pack -- gcp-iam-service-account-no-admin (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `has_admin_role` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_iam_service_account_no_admin

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.has_admin_role == true
}

outcome := "PASS" if {
	input.has_admin_role == false
}
