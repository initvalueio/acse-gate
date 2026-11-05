# gcp-storage-bucket-not-public: Terraform plan -> the canonical facts of `provider-packs/gcp/checks/facts.py` (ledger 07 OD-1, lane B).
#
# Input: `terraform show -json` of the plan. For each planned bucket (and public grant on a bucket outside the plan) the class judges, `facts` is exactly
# the fact dictionary facts.py sets from the API response for the same resource, or `{}` when the plan cannot
# establish it; `results` adds the outcome of the class's own policy.rego over those facts (the same Rego detect runs)
# and, when no fact is set, why (`unknown_reason`, acse-gate-finding-1.0). An unknown is never a failure (OD-10).
# Partial: the bucket's IAM policy and ACLs usually live outside the plan.
# Self-contained on purpose: every helper is repeated in each class, so the class digest (acse-class-digest-1) covers
# everything the class evaluates. Paired fixtures in tests/parity.json hold it equal to facts.py (lane B's conformance
# test, provider-packs/tests/test_gate_normaliser_parity.py).
package acse.normalisers.terraform_plan.gcp_storage_bucket_not_public

import rego.v1

check_id := "gcp-storage-bucket-not-public"

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

# The bucket's `public_access` as facts.py `bucket_public_access` decides it:
# - false when public access prevention is enforced (it blocks every public grant);
# - true when an IAM grant or ACL entry in the plan gives `allUsers` or `allAuthenticatedUsers` access to the bucket;
# - false when uniform bucket-level access is on and an authoritative `google_storage_bucket_iam_policy` for the bucket
#   is in the plan with no public binding (the plan then shows the whole policy, as the API read does);
# - otherwise no fact: the bucket's IAM policy and ACLs are held outside the plan.
#
# Judged: every bucket the plan writes, every unchanged bucket a written grant names, and every written public (or
# not yet known) grant whose bucket is not in the plan, reported unknown on the grant itself.
planned[address] := rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == "google_storage_bucket"
	judged_bucket(rc)
	address := rc.address
}

judged_bucket(rc) if writes(rc)

judged_bucket(rc) if {
	"no-op" in rc.change.actions
	some g in grants_on(bucket_name(rc))
	writes(g)
}

PUBLIC := {"allUsers", "allAuthenticatedUsers"}

ACL_TYPES := {"google_storage_bucket_acl", "google_storage_default_object_acl"}

GRANT_TYPES := {
	"google_storage_bucket_iam_member",
	"google_storage_bucket_iam_binding",
	"google_storage_bucket_iam_policy",
	"google_storage_bucket_acl",
	"google_storage_default_object_acl",
}

bucket_name(rc) := n if {
	not unknown(rc, "name")
	n := after(rc, "name")
	is_string(n)
}

# A grant names its bucket as `<name>` or `b/<name>`.
names_bucket(g, name) if after(g, "bucket") == name

names_bucket(g, name) if after(g, "bucket") == concat("", ["b/", name])

grants_on(name) := [g |
	some g in input.resource_changes
	g.mode == "managed"
	g.type in GRANT_TYPES
	present(g)
	not unknown(g, "bucket")
	names_bucket(g, name)
]

policy_bindings(g) := bindings if {
	document := json.unmarshal(after(g, "policy_data"))
	bindings := object.get(document, "bindings", [])
	is_array(bindings)
}

acl_entity(entry) := parts[1] if {
	parts := split(entry, ":")
	count(parts) == 2
}

public_grant(g) if {
	g.type == "google_storage_bucket_iam_member"
	after(g, "member") in PUBLIC
}

public_grant(g) if {
	g.type == "google_storage_bucket_iam_binding"
	some m in as_list(after(g, "members"))
	m in PUBLIC
}

public_grant(g) if {
	g.type == "google_storage_bucket_iam_policy"
	some b in policy_bindings(g)
	some m in as_list(object.get(b, "members", null))
	m in PUBLIC
}

public_grant(g) if {
	g.type in ACL_TYPES
	some entry in as_list(after(g, "role_entity"))
	acl_entity(entry) in PUBLIC
}

public_grant(g) if {
	g.type == "google_storage_bucket_acl"
	after(g, "predefined_acl") in {"publicRead", "publicReadWrite"}
}

grant_unknown(g) if {
	g.type == "google_storage_bucket_iam_member"
	unknown(g, "member")
}

grant_unknown(g) if {
	g.type == "google_storage_bucket_iam_binding"
	block_unknown(g, "members")
}

grant_unknown(g) if {
	g.type == "google_storage_bucket_iam_policy"
	unknown(g, "policy_data")
}

grant_unknown(g) if {
	g.type in ACL_TYPES
	block_unknown(g, "role_entity")
}

# A grant whose bucket is not known yet could name any bucket.
stray_grant if {
	some g in input.resource_changes
	g.mode == "managed"
	g.type in GRANT_TYPES
	present(g)
	unknown(g, "bucket")
}

pap(rc) := v if {
	not unknown(rc, "public_access_prevention")
	v := after(rc, "public_access_prevention")
	is_string(v)
}

value(rc) := false if {
	pap(rc) == "enforced"
} else if {
	is_string(pap(rc))
	some g in grants_on(bucket_name(rc))
	public_grant(g)
} else := false if {
	is_string(pap(rc))
	not unknown(rc, "uniform_bucket_level_access")
	after(rc, "uniform_bucket_level_access") == true
	grants := grants_on(bucket_name(rc))
	some policy in grants
	policy.type == "google_storage_bucket_iam_policy"
	is_array(policy_bindings(policy))
	every g in grants {
		not public_grant(g)
		not grant_unknown(g)
	}
	not stray_grant
}

reason(rc) := "value_known_after_apply" if {
	unknown(rc, "public_access_prevention")
} else := "resource_outside_input"

# A written public (or not yet known) grant on a bucket the plan does not hold: the bucket's public access
# prevention is outside the input, so the class reads unknown on the grant.
orphans[address] := g if {
	some g in input.resource_changes
	g.mode == "managed"
	g.type in GRANT_TYPES
	writes(g)
	not bucket_in_plan(g)
	risky_grant(g)
	address := g.address
}

risky_grant(g) if public_grant(g)

risky_grant(g) if grant_unknown(g)

bucket_in_plan(g) if {
	some b in input.resource_changes
	b.mode == "managed"
	b.type == "google_storage_bucket"
	present(b)
	names_bucket(g, bucket_name(b))
}

facts[address] := {} if some address, _ in orphans

results[address] := {
	"resource_type": g.type,
	"facts": {},
	"outcome": outcome({}),
	"unknown_reason": "resource_outside_input",
} if some address, g in orphans

# -- Facts, the class's outcome, and why a fact is missing ----------------------------------------------------------

facts[address] := fact(rc) if some address, rc in planned

results[address] := object.union(
	{"resource_type": rc.type, "facts": f, "outcome": outcome(f)},
	object.union(project_part(rc), reason_part(rc, f)),
) if {
	some address, rc in planned
	f := facts[address]
}

fact(rc) := {"public_access": v} if {
	v := value(rc)
} else := {}

outcome(f) := o if {
	o := data.acse.gcp.checks.gcp_storage_bucket_not_public.outcome with input as f
}

project_part(rc) := {"project": p} if {
	p := after(rc, "project")
	is_string(p)
} else := {}

reason_part(rc, f) := {"unknown_reason": reason(rc)} if f == {}

reason_part(_, f) := {} if f != {}
