# gcp-iam-service-account-no-admin: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each project IAM grant (member, binding or authoritative policy) the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: the plan cannot show that an account holds no admin role elsewhere.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_iam_service_account_no_admin

import rego.v1

check_id := "gcp-iam-service-account-no-admin"

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

# A service account holding Owner, Editor or an `*Admin` / `*admin` role on the project, as the plan grants it
# (`google_project_iam_member`, `_binding`, or the authoritative `_policy`). Only a grant that can give a service account
# such a role is judged: one whose service account member is known (true), or whose member is not known yet (unknown).
# The plan cannot show that an account has no such grant elsewhere, so it never sets false.
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	writes(rc)
	judged(rc)
	address := rc.address
}

admin_role(r) if r in {"roles/owner", "roles/editor"}

admin_role(r) if {
	is_string(r)
	endswith(lower(r), "admin")
}

sa_member(m) if {
	is_string(m)
	startswith(m, "serviceAccount:")
}

policy_bindings(rc) := bindings if {
	document := json.unmarshal(after(rc, "policy_data"))
	bindings := object.get(document, "bindings", [])
	is_array(bindings)
}

judged(rc) if {
	rc.type == "google_project_iam_member"
	admin_role(after(rc, "role"))
	unknown(rc, "member")
}

judged(rc) if {
	rc.type == "google_project_iam_member"
	admin_role(after(rc, "role"))
	sa_member(after(rc, "member"))
}

judged(rc) if {
	rc.type == "google_project_iam_binding"
	admin_role(after(rc, "role"))
	block_unknown(rc, "members")
}

judged(rc) if {
	rc.type == "google_project_iam_binding"
	admin_role(after(rc, "role"))
	some m in as_list(after(rc, "members"))
	sa_member(m)
}

judged(rc) if {
	rc.type == "google_project_iam_policy"
	unknown(rc, "policy_data")
}

judged(rc) if {
	rc.type == "google_project_iam_policy"
	some b in policy_bindings(rc)
	admin_role(b.role)
	some m in as_list(object.get(b, "members", null))
	sa_member(m)
}

value(rc) if {
	rc.type == "google_project_iam_member"
	not unknown(rc, "member")
	sa_member(after(rc, "member"))
} else if {
	rc.type == "google_project_iam_binding"
	not block_unknown(rc, "members")
	some m in as_list(after(rc, "members"))
	sa_member(m)
} else if {
	rc.type == "google_project_iam_policy"
	not unknown(rc, "policy_data")
	some b in policy_bindings(rc)
	admin_role(b.role)
	some m in as_list(object.get(b, "members", null))
	sa_member(m)
}

reason(_) := "value_known_after_apply"

# -- Facts, the class's outcome, and why a fact is missing ----------------------------------------------------------

facts[address] := fact(rc) if some address, rc in planned

results[address] := object.union(
	{"resource_type": rc.type, "facts": f, "outcome": outcome(f)},
	object.union(project_part(rc), reason_part(rc, f)),
) if {
	some address, rc in planned
	f := facts[address]
}

fact(rc) := {"has_admin_role": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_iam_service_account_no_admin.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
