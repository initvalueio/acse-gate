# gcp-iam-no-basic-roles: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each project IAM grant (member, binding or authoritative policy) the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: only an authoritative project IAM policy in the plan shows every grant.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_iam_no_basic_roles

import rego.v1

check_id := "gcp-iam-no-basic-roles"

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

ROLES := {"roles/owner", "roles/editor", "roles/viewer"}

COUNTED_PREFIXES := ["user:", "group:", "serviceAccount:", "domain:"]

# Project IAM in the plan: a grant of one of ROLES (`google_project_iam_member` or `_binding`), or the authoritative
# `google_project_iam_policy`, which shows the whole policy as the API read does. A member or binding grant gives a
# count of at least its own members: a positive count fails the class whatever else the policy holds, while a count of
# zero says nothing about the rest of the policy and is not a fact. Grants of other roles are not judged.
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	writes(rc)
	judged(rc)
	address := rc.address
}

judged(rc) if {
	rc.type in {"google_project_iam_member", "google_project_iam_binding"}
	not unknown(rc, "role")
	after(rc, "role") in ROLES
}

judged(rc) if rc.type == "google_project_iam_policy"

counted(m) if {
	is_string(m)
	some prefix in COUNTED_PREFIXES
	startswith(m, prefix)
}

policy_bindings(rc) := bindings if {
	document := json.unmarshal(after(rc, "policy_data"))
	bindings := object.get(document, "bindings", [])
	is_array(bindings)
}

grant_known(rc) if {
	rc.type == "google_project_iam_member"
	not unknown(rc, "member")
}

grant_known(rc) if {
	rc.type == "google_project_iam_binding"
	not block_unknown(rc, "members")
}

grant_known(rc) if {
	rc.type == "google_project_iam_policy"
	not unknown(rc, "policy_data")
	is_array(policy_bindings(rc))
}

granted(rc) := {m | m := after(rc, "member"); counted(m)} if {
	rc.type == "google_project_iam_member"
} else := {m | some m in as_list(after(rc, "members")); counted(m)} if {
	rc.type == "google_project_iam_binding"
} else := {m |
	some b in policy_bindings(rc)
	b.role in ROLES
	some m in as_list(object.get(b, "members", null))
	counted(m)
} if {
	rc.type == "google_project_iam_policy"
}

value(rc) := n if {
	grant_known(rc)
	n := count(granted(rc))
	exact_or_positive(rc, n)
}

exact_or_positive(rc, _) if rc.type == "google_project_iam_policy"

exact_or_positive(_, n) if n > 0

reason(rc) := "fact_not_in_input" if {
	grant_known(rc)
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

fact(rc) := {"basic_role_members": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_iam_no_basic_roles.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
