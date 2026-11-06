# gcp-compute-no-default-service-account: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each planned google_compute_instance the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: a `service_account` block without an email gets the default account at apply.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_compute_no_default_service_account

import rego.v1

check_id := "gcp-compute-no-default-service-account"

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

DEFAULT_SA_SUFFIX := "-compute@developer.gserviceaccount.com"

accounts_unknown(rc) if block_unknown(rc, "service_account")

default_account(a) if {
	is_string(a.email)
	endswith(a.email, DEFAULT_SA_SUFFIX)
}

email_unknown(rc, i) if rc.change.after_unknown.service_account[i].email == true

# The Compute Engine default service account is attached. No `service_account` block passes. A block that names no
# email gets the default account at apply, so its email is known only then.
value(rc) if {
	not accounts_unknown(rc)
	some a in as_list(after(rc, "service_account"))
	default_account(a)
} else := false if {
	not accounts_unknown(rc)
	accounts := as_list(after(rc, "service_account"))
	every i, a in accounts {
		not email_unknown(rc, i)
		is_object(a)
	}
}

reason(rc) := "value_known_after_apply" if {
	accounts_unknown(rc)
} else := "value_known_after_apply" if {
	some i, _ in as_list(after(rc, "service_account"))
	email_unknown(rc, i)
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

fact(rc) := {"uses_default_service_account": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_compute_no_default_service_account.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
