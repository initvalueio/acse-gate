# GCP pack -- gcp-iam-no-basic-roles (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `basic_role_members` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_iam_no_basic_roles

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	is_number(input.basic_role_members)
	input.basic_role_members > 0
}

outcome := "PASS" if {
	input.basic_role_members == 0
}
