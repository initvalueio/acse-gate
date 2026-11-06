# gcp-compute-os-login: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each planned google_compute_instance the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: unset on the instance, the project's metadata decides, and it is often outside the plan.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_compute_os_login

import rego.v1

check_id := "gcp-compute-os-login"

# The resources the class judges: managed google_compute_instance resources the plan creates or updates. A no-op, a read or a
# delete changes nothing the gate can stop; detect covers what already exists.
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "google_compute_instance"
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

TRUE_VALUES := {"true", "1", "yes", "y", "on"}

flag(v) if {
	is_string(v)
	lower(trim_space(v)) in TRUE_VALUES
} else := false

metadata_unknown(rc) if unknown(rc, "metadata")

metadata_unknown(rc) if rc.change.after_unknown.metadata[KEY] == true

metadata(rc) := m if {
	m := after(rc, "metadata")
	is_object(m)
} else := {} if {
	after(rc, "metadata") == null
}

KEY := "enable-oslogin"

# `enable-oslogin` on the instance, else on its project (facts.py `_flag`). The project's metadata is read from the
# plan's own project metadata resources for the instance's project; when the plan holds none, the project's value is
# outside the input.
value(rc) := v if {
	not metadata_unknown(rc)
	m := metadata(rc)
	KEY in object.keys(m)
	v := flag(m[KEY])
} else := v if {
	not metadata_unknown(rc)
	not KEY in object.keys(metadata(rc))
	project := after(rc, "project")
	is_string(project)
	settings := project_settings(project)
	count(settings) == 1
	some setting in settings
	v := flag(setting)
}

# The project's own value of KEY as the plan shows it: an item's value, or an authoritative metadata map's entry
# ("" when the map leaves it unset, which reads as off, as facts.py reads an absent key).
project_settings(project) := items(project) | maps(project)

items(project) := {v |
	some p in input.resource_changes
	p.mode == "managed"
	p.type == "google_compute_project_metadata_item"
	present(p)
	not unknown(p, "key")
	after(p, "key") == KEY
	not unknown(p, "project")
	after(p, "project") == project
	not unknown(p, "value")
	v := after(p, "value")
}

maps(project) := {v |
	some p in input.resource_changes
	p.mode == "managed"
	p.type == "google_compute_project_metadata"
	present(p)
	not unknown(p, "project")
	after(p, "project") == project
	not metadata_unknown(p)
	m := after(p, "metadata")
	is_object(m)
	v := object.get(m, KEY, "")
}

reason(rc) := "value_known_after_apply" if {
	metadata_unknown(rc)
} else := "resource_outside_input"

# The class's Fix directive adds a project metadata item. Every failure the plan can establish comes from a setting the
# plan itself holds (the instance's own key, or the project's item or map), which an added item does not override, so
# the gate offers no suggestion for it (gate/finding.rego reads this set).
directive_not_applicable contains address if {
	some address, rc in planned
	value(rc) == false
}

# -- Facts, the class's outcome, and why a fact is missing ----------------------------------------------------------

facts[address] := fact(rc) if some address, rc in planned

results[address] := object.union(
	{"resource_type": rc.type, "facts": f, "outcome": outcome(f)},
	object.union(project_part(rc), reason_part(rc, f)),
) if {
	some address, rc in planned
	f := facts[address]
}

fact(rc) := {"os_login_enabled": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_compute_os_login.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
