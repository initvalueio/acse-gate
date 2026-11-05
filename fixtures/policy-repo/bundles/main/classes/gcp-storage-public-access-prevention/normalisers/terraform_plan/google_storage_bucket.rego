# gcp-storage-public-access-prevention: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each planned google_storage_bucket the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: an unset `public_access_prevention` is decided at apply.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_storage_public_access_prevention

import rego.v1

check_id := "gcp-storage-public-access-prevention"

# The resources the class judges: managed google_storage_bucket resources the plan creates or updates. A no-op, a read or a
# delete changes nothing the gate can stop; detect covers what already exists.
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "google_storage_bucket"
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

# `public_access_prevention` as planned: enforced, or inherited (an organization policy may still enforce it; facts.py
# reads the bucket's own setting the same way). Optional and computed: unset on create, it is known only after apply.
value(rc) if {
	not unknown(rc, "public_access_prevention")
	after(rc, "public_access_prevention") == "enforced"
} else := false if {
	not unknown(rc, "public_access_prevention")
	after(rc, "public_access_prevention") in {"inherited", "unspecified"}
}

reason(rc) := "value_known_after_apply" if {
	unknown(rc, "public_access_prevention")
} else := "fact_not_in_input"

# -- Facts, the class's outcome, and why a fact is missing ----------------------------------------------------------

facts[address] := fact(rc) if some address, rc in planned

results[address] := object.union(
	{"resource_type": rc.type, "facts": f, "outcome": outcome(f)},
	object.union(project_part(rc), reason_part(rc, f)),
) if {
	some address, rc in planned
	f := facts[address]
}

fact(rc) := {"public_access_prevention_enforced": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_storage_public_access_prevention.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
