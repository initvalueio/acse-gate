# GCP pack -- gcp-vpc-firewall-logging (W9-1, ADR-0074 Amendment 2).
#
# Reads only the canonical fact `firewall_logging_enabled` that `gcp/checks/facts.py` sets.
# The runtime refuses any other key or a value of the wrong type before OPA runs (ADR-0010 section H).
#
# Total by construction: `default` makes an absent fact UNKNOWN, never an undefined result, and UNKNOWN is never
# PASS (ADR-0010).
package acse.gcp.checks.gcp_vpc_firewall_logging

import rego.v1

default outcome := "UNKNOWN"

outcome := "FAIL" if {
	input.firewall_logging_enabled == false
}

outcome := "PASS" if {
	input.firewall_logging_enabled == true
}
