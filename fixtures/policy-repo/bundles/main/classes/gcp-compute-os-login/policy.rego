# GCP pack -- gcp-compute-os-login (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `os_login_enabled` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_compute_os_login

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.os_login_enabled == false
}

outcome := "PASS" if {
	input.os_login_enabled == true
}
