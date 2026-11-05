# GCP pack -- gcp-compute-block-project-ssh-keys (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `project_ssh_keys_blocked` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_compute_block_project_ssh_keys

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.project_ssh_keys_blocked == false
}

outcome := "PASS" if {
	input.project_ssh_keys_blocked == true
}
