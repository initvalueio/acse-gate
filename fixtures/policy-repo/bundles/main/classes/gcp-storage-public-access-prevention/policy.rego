# GCP pack -- gcp-storage-public-access-prevention (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `public_access_prevention_enforced` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_storage_public_access_prevention

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.public_access_prevention_enforced == false
}

outcome := "PASS" if {
	input.public_access_prevention_enforced == true
}
