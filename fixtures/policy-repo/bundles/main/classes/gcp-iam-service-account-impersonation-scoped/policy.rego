# GCP pack -- gcp-iam-service-account-impersonation-scoped (W12-2, fix summary C7; ADR-0074 Amendment 4 section 4).
#
# Reads only the canonical fact `broad_acting_grant` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_iam_service_account_impersonation_scoped

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.broad_acting_grant == true
}

outcome := "PASS" if {
	input.broad_acting_grant == false
}
