# gcp-compute-no-default-sa-full-access: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each planned google_compute_instance the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: a `service_account` block without an email gets the default account at apply.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_compute_no_default_sa_full_access

import rego.v1

check_id := "gcp-compute-no-default-sa-full-access"

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

# The default service account with the `cloud-platform` scope. Terraform accepts the scope's alias, so both spellings
# count; the API returns only the URL.
FULL_API_SCOPE := "https://www.googleapis.com/auth/cloud-platform"

full_scope(s) if s == FULL_API_SCOPE

full_scope(s) if s == "cloud-platform"

scopes_unknown(rc, i) if rc.change.after_unknown.service_account[i].scopes == true

scopes_unknown(rc, i) if rc.change.after_unknown.service_account[i].scopes[_] == true

full(a) if {
	some s in as_list(object.get(a, "scopes", null))
	full_scope(s)
}

narrow(a) if {
	every s in as_list(object.get(a, "scopes", null)) {
		not full_scope(s)
	}
}

# An account that could still turn out to be the default one with full access.
undecided(rc) if {
	some i, a in as_list(after(rc, "service_account"))
	email_unknown(rc, i)
	not known_narrow(rc, i, a)
}

undecided(rc) if {
	some i, a in as_list(after(rc, "service_account"))
	scopes_unknown(rc, i)
	not known_other(rc, i, a)
}

known_narrow(rc, i, a) if {
	not scopes_unknown(rc, i)
	narrow(a)
}

known_other(rc, i, a) if {
	not email_unknown(rc, i)
	not default_account(a)
}

value(rc) if {
	not accounts_unknown(rc)
	some i, a in as_list(after(rc, "service_account"))
	not email_unknown(rc, i)
	not scopes_unknown(rc, i)
	default_account(a)
	full(a)
} else := false if {
	not accounts_unknown(rc)
	is_array(as_list(after(rc, "service_account")))
	not undecided(rc)
}

reason(rc) := "value_known_after_apply" if {
	accounts_unknown(rc)
} else := "value_known_after_apply" if {
	undecided(rc)
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

fact(rc) := {"default_sa_full_api_access": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_compute_no_default_sa_full_access.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
