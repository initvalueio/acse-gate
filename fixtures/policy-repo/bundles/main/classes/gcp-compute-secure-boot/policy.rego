# GCP pack -- gcp-compute-secure-boot (W11-2, fix summary B5).
#
# Reads only the canonical fact `secure_boot_enabled` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_compute_secure_boot

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.secure_boot_enabled == false
}

outcome := "PASS" if {
	input.secure_boot_enabled == true
}
