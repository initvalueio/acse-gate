# GCP pack -- gcp-iam-no-project-level-sa-impersonation (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `project_level_sa_impersonation_members` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_iam_no_project_level_sa_impersonation

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	is_number(input.project_level_sa_impersonation_members)
	input.project_level_sa_impersonation_members > 0
}

outcome := "PASS" if {
	input.project_level_sa_impersonation_members == 0
}
