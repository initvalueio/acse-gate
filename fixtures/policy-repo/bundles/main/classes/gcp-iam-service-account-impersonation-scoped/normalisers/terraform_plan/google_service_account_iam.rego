# gcp-iam-service-account-impersonation-scoped: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each service account IAM grant (member, binding or policy) the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: only an authoritative service account IAM policy in the plan shows every grant.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_iam_service_account_impersonation_scoped

import rego.v1

check_id := "gcp-iam-service-account-impersonation-scoped"

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

# Who can act as the service account, from its own IAM policy in the plan (`google_service_account_iam_member`,
# `_binding`, or the authoritative `_policy`): `broad_acting_grant` is true when a binding of an acting role has a broad
# member (facts.py `broad_acting_member`). Only the authoritative policy shows every binding, so only it sets false; a
# member or binding grant is judged when it is broad (true) or not known yet (unknown).
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	writes(rc)
	judged(rc)
	address := rc.address
}

PUBLIC_MEMBERS := {"allUsers", "allAuthenticatedUsers"}

SA_ACTING_ROLES := {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator", "roles/iam.workloadIdentityUser"}

broad_member(m, _) if m in PUBLIC_MEMBERS

broad_member(m, _) if {
	is_string(m)
	startswith(m, "domain:")
}

broad_member(m, conditioned) if {
	conditioned == false
	is_string(m)
	startswith(m, "principalSet://")
	endswith(m, "/*")
}

conditioned(rc) if {
	count(as_list(after(rc, "condition"))) > 0
} else := false

policy_bindings(rc) := bindings if {
	document := json.unmarshal(after(rc, "policy_data"))
	bindings := object.get(document, "bindings", [])
	is_array(bindings)
}

binding_conditioned(b) if {
	object.get(b, "condition", null) != null
	object.get(b, "condition", null) != {}
} else := false

member_unknown(rc) if {
	rc.type == "google_service_account_iam_member"
	unknown(rc, "member")
}

member_unknown(rc) if {
	rc.type == "google_service_account_iam_binding"
	block_unknown(rc, "members")
}

member_unknown(rc) if {
	rc.type in {"google_service_account_iam_member", "google_service_account_iam_binding"}
	block_unknown(rc, "condition")
}

acting(rc) if {
	rc.type in {"google_service_account_iam_member", "google_service_account_iam_binding"}
	not unknown(rc, "role")
	after(rc, "role") in SA_ACTING_ROLES
}

broad_grant(rc) if {
	rc.type == "google_service_account_iam_member"
	broad_member(after(rc, "member"), conditioned(rc))
}

broad_grant(rc) if {
	rc.type == "google_service_account_iam_binding"
	some m in as_list(after(rc, "members"))
	broad_member(m, conditioned(rc))
}

judged(rc) if {
	acting(rc)
	member_unknown(rc)
}

judged(rc) if {
	acting(rc)
	not member_unknown(rc)
	broad_grant(rc)
}

judged(rc) if rc.type == "google_service_account_iam_policy"

value(rc) if {
	acting(rc)
	not member_unknown(rc)
	broad_grant(rc)
} else if {
	rc.type == "google_service_account_iam_policy"
	not unknown(rc, "policy_data")
	some b in policy_bindings(rc)
	b.role in SA_ACTING_ROLES
	some m in as_list(object.get(b, "members", null))
	broad_member(m, binding_conditioned(b))
} else := false if {
	rc.type == "google_service_account_iam_policy"
	not unknown(rc, "policy_data")
	is_array(policy_bindings(rc))
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

fact(rc) := {"broad_acting_grant": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_iam_service_account_impersonation_scoped.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
