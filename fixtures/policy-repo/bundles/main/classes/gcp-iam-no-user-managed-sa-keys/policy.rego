# GCP pack -- gcp-iam-no-user-managed-sa-keys (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `user_managed_keys` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_iam_no_user_managed_sa_keys

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	is_number(input.user_managed_keys)
	input.user_managed_keys > 0
}

outcome := "PASS" if {
	input.user_managed_keys == 0
}
