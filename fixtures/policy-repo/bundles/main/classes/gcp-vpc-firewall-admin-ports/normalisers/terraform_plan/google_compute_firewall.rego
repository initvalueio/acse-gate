# gcp-vpc-firewall-admin-ports: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each planned google_compute_firewall the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: an unset `source_ranges` (or a computed direction) is decided at apply.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_vpc_firewall_admin_ports

import rego.v1

check_id := "gcp-vpc-firewall-admin-ports"

# The resources the class judges: managed google_compute_firewall resources the plan creates or updates. A no-op, a read or a
# delete changes nothing the gate can stop; detect covers what already exists.
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "google_compute_firewall"
	writes(rc)
	address := rc.address
}

writes(rc) if "create" in rc.change.actions

writes(rc) if "update" in rc.change.actions

# The plan's own view of what exists after it: anything it creates, updates or leaves unchanged.
present(rc) if writes(rc)

present(rc) if "no-op" in rc.change.actions

after(rc, name) := object.get(rc.change.after, name, null)

as_list(x) := x if is_array(x)

as_list(x) := [] if x == null

# `after_unknown` marks a value known only after apply.
unknown(rc, _) if rc.change.after_unknown == true

unknown(rc, name) if rc.change.after_unknown[name] == true

block_unknown(rc, name) if unknown(rc, name)

block_unknown(rc, name) if rc.change.after_unknown[name][_] == true

PORTS := [22, 3389]

# -- direction: INGRESS when the rule says so, or when the configuration leaves it unset (the API's default, as
# facts.py reads an absent direction). Optional and computed, so an unset direction is unknown in a create's plan.
direction(rc) := d if {
	not unknown(rc, "direction")
	d := after(rc, "direction")
	is_string(d)
} else := "INGRESS" if {
	not unknown(rc, "direction")
	after(rc, "direction") == null
} else := "INGRESS" if {
	unknown(rc, "direction")
	not configured(rc, "direction")
}

configured(rc, name) if {
	r := config_resource(rc)
	name in object.keys(object.get(r, "expressions", {}))
}

config_resource(rc) := r if {
	m := config_module(rc)
	some r in m.resources
	r.mode == "managed"
	r.address == concat(".", [rc.type, rc.name])
}

config_module(rc) := input.configuration.root_module if {
	not rc.module_address
} else := m if {
	path := [step | some name in module_names(rc.module_address); some step in ["module_calls", name, "module"]]
	m := object.get(input.configuration.root_module, path, null)
	is_object(m)
}

module_names(address) := names if {
	parts := split(regex.replace(address, `\[[^\]]*\]`, ""), ".")
	names := [parts[i] | some i in numbers.range(1, count(parts) - 1); i % 2 == 1]
}

# -- the rule is off for this check: egress, disabled, or a deny rule.
off(rc) if {
	d := direction(rc)
	d != "INGRESS"
}

off(rc) if after(rc, "disabled") == true

off(rc) if {
	not unknown(rc, "deny")
	count(as_list(after(rc, "deny"))) > 0
}

on(rc) if {
	direction(rc) == "INGRESS"
	not after(rc, "disabled") == true
	not unknown(rc, "deny")
	count(as_list(after(rc, "deny"))) == 0
	not block_unknown(rc, "allow")
}

# -- ports: an `allow` entry for all protocols or TCP; no ports means every port.
relevant(a) if lower(a.protocol) in {"all", "tcp", "6"}

ranges(a) := [[0, 65535]] if {
	lower(a.protocol) == "all"
} else := [[0, 65535]] if {
	count(as_list(object.get(a, "ports", null))) == 0
} else := rs if {
	ports := as_list(object.get(a, "ports", null))
	rs := [port_range(p) | some p in ports]
	count(rs) == count(ports)
}

port_range(p) := [to_number(p), to_number(p)] if {
	regex.match(`^[0-9]+$`, p)
} else := [to_number(parts[0]), to_number(parts[1])] if {
	regex.match(`^[0-9]+-[0-9]+$`, p)
	parts := split(p, "-")
}

covering(rc) if {
	some a in as_list(after(rc, "allow"))
	relevant(a)
	some r in ranges(a)
	some p in PORTS
	r[0] <= p
	p <= r[1]
}

invalid(rc) if {
	some a in as_list(after(rc, "allow"))
	relevant(a)
	not ranges(a)
}

# -- sources: a range with prefix length 0 is the world (0.0.0.0/0, ::/0).
sources_unknown(rc) if block_unknown(rc, "source_ranges")

world(c) if {
	is_string(c)
	endswith(c, "/0")
	net.cidr_is_valid(c)
}

from_world(rc) if {
	some c in as_list(after(rc, "source_ranges"))
	world(c)
}

value(rc) := false if {
	off(rc)
} else if {
	on(rc)
	covering(rc)
	not sources_unknown(rc)
	from_world(rc)
} else := false if {
	on(rc)
	covering(rc)
	not sources_unknown(rc)
	is_array(as_list(after(rc, "source_ranges")))
} else := false if {
	on(rc)
	not covering(rc)
	not invalid(rc)
}

reason(rc) := "fact_not_in_input" if {
	invalid(rc)
} else := "value_known_after_apply"

# -- Facts, the class's outcome, and why a fact is missing ----------------------------------------------------------

facts[address] := fact(rc) if some address, rc in planned

results[address] := object.union(
	{"resource_type": rc.type, "facts": f, "outcome": outcome(f)},
	object.union(project_part(rc), reason_part(rc, f)),
) if {
	some address, rc in planned
	f := facts[address]
}

fact(rc) := {"admin_port_open_to_world": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_vpc_firewall_admin_ports.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
