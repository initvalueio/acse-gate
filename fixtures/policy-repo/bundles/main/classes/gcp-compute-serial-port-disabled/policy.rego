# GCP pack -- gcp-compute-serial-port-disabled (W5-9, ADR-0074 decision 1).
#
# Reads only the canonical fact `serial_port_enabled` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_compute_serial_port_disabled

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.serial_port_enabled == true
}

outcome := "PASS" if {
	input.serial_port_enabled == false
}
