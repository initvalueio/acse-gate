# The gate's entry point (ledger 07 lane B; spec 07 Amendment 2026-11-05 G-3, G-4, G-5): the bundle's
# `bundles/<name>/gate/finding.rego` (common/policy-repo-layout-1.2 kind bundle_gate_logic).
#
# `data.acse.gate.finding` is the acse-gate-finding-1.0 document (protocols/acse-gate-finding-1.0, shared interface
# I-1) for one Terraform plan. It never leaves the runner. How the gate calls it, with nothing but plain `opa`:
#
#   opa eval --format json --capabilities <the runtime's opa_capabilities.json> \
#     --input <terraform show -json of the plan> \
#     --data "acse_bundle.control:bundles/<name>/bundle.json" \
#     --data "acse_bundle.classes:bundles/<name>/classes" \
#     --data "bundles/<name>/gate" \
#     [--data "acse_bundle.tfvars:<tfvars JSON>"] \
#     'data.acse.gate.finding'
#
# - data.acse_bundle.control is bundle.json (common/gate-bundle-1.0): the modes and the label to project map.
# - data.acse_bundle.classes.<check_id> is that class's metadata.yaml and directive.json, which opa's loader merges
#   (their members never overlap). The same --data loads every class's policy.rego and normalisers, whose packages
#   carry their own paths.
# - data.acse_bundle.tfvars is optional: the tfvars JSON, read only to name a resource's project when neither the
#   resource nor the plan's own variables do.
#
# Every class runs through its Terraform plan normaliser, package acse.normalisers.terraform_plan.<check id with _>,
# which gives `check_id` and `results[address]` (resource_type, facts, the class's policy outcome, the project when
# known, the unknown reason). This file only assembles: the mode per resource (G-5), the controls, and on a failure the
# suggested change rendered from the class's Fix directive (OD-8). An unknown is never a failure (OD-10).
package acse.gate

import rego.v1

default control := {}

control := data.acse_bundle.control

default normalisers := {}

normalisers := data.acse.normalisers.terraform_plan

# Each class the bundle ran: its check id and its normaliser's package.
ran[cid] := pkg if {
	some pkg, normaliser in normalisers
	cid := normaliser.check_id
	is_string(cid)
}

finding := {
	"gate_finding_version": "1.0",
	"input_kind": "terraform_plan",
	"classes": [{"check_id": cid, "mode": class_mode(cid)} | some cid in sort(object.keys(ran))],
	"findings": [f | some f in findings],
}

findings contains f if {
	some cid, pkg in ran
	some address, r in normalisers[pkg].results
	outcome := lower(r.outcome)
	outcome in {"pass", "fail", "unknown"}
	project := project_of(r)
	base := {
		"check_id": cid,
		"outcome": outcome,
		"mode": resource_mode(cid, project),
		"address": address,
		"resource_type": r.resource_type,
		"controls": controls(cid),
	}
	f := object.union(base, detail(cid, outcome, r, project, directive_offered(pkg, address)))
}

# A normaliser may name, in `directive_not_applicable`, the failures its class's directive cannot fix (the delta would
# not change the setting the plan holds); those carry no suggestion.
directive_offered(pkg, address) := false if {
	normalisers[pkg].directive_not_applicable[address]
} else := true

# -- Mode (common/gate-bundle-1.0) ------------------------------------------------------------------------------------
# If the resource's project carries labels with a mode set for the class: enforce when any says enforce, else observe.
# Otherwise the class's mode; otherwise default_mode. A resource whose project the plan does not show takes the
# class's mode.

fallback_mode := m if {
	m := control.default_mode
	m in {"observe", "enforce"}
} else := "observe"

class_entries(cid) := [e | some e in object.get(control, "classes", []); e.check_id == cid]

class_mode(cid) := m if {
	[e] := class_entries(cid)
	m := e.mode
	m in {"observe", "enforce"}
} else := fallback_mode

label_modes(cid, project) := {lm.mode |
	some e in class_entries(cid)
	some lm in object.get(e, "label_modes", [])
	some label in object.get(control, "labels", [])
	label.dimension == lm.dimension
	label.value == lm.value
	some scope in label.scopes
	scope.kind == "gcp_project"
	scope.id == project
}

resource_mode(cid, project) := "enforce" if {
	"enforce" in label_modes(cid, project)
} else := "observe" if {
	count(label_modes(cid, project)) > 0
} else := class_mode(cid)

# -- The resource's project -------------------------------------------------------------------------------------------
# The resource's own `project`; else the google provider's configured project, as a constant or a variable (the plan's
# own variables, else the tfvars JSON); else none.

project_of(r) := r.project if {
	is_string(r.project)
} else := p if {
	p := provider_project
	is_string(p)
} else := null

provider_project := p if {
	p := input.configuration.provider_config.google.expressions.project.constant_value
} else := p if {
	[reference] := input.configuration.provider_config.google.expressions.project.references
	startswith(reference, "var.")
	p := variable_value(substring(reference, 4, -1))
}

variable_value(name) := v if {
	v := input.variables[name].value
} else := v if {
	v := data.acse_bundle.tfvars[name]
}

# -- Controls (policy-metadata-1.1 crosswalk) --------------------------------------------------------------------------

class_doc(cid) := d if {
	d := data.acse_bundle.classes[cid]
	is_object(d)
} else := {}

controls(cid) := [control_entry(x) | some x in object.get(class_doc(cid), "crosswalk", [])]

control_entry(x) := {"framework_id": x.framework_id, "control_id": x.control_id, "control_title": x.control_title} if {
	is_string(x.control_title)
} else := {"framework_id": x.framework_id, "control_id": x.control_id}

# -- Outcome detail -----------------------------------------------------------------------------------------------------

UNKNOWN_REASONS := {"value_known_after_apply", "resource_outside_input", "fact_not_in_input"}

detail(_, "pass", _, _, _) := {}

detail(_, "unknown", r, _, _) := {"unknown_reason": reason} if {
	reason := r.unknown_reason
	reason in UNKNOWN_REASONS
} else := {"unknown_reason": "fact_not_in_input"}

# acse-gate-finding-1.0 has one reason for a failure without a suggestion, `no_directive`; it is also what a failure
# whose directive does not apply, or does not render, carries.
detail(cid, "fail", r, project, true) := {"suggestion": s} if {
	s := suggestion(cid, r, project)
} else := {"no_suggestion": "no_directive"}

detail(_, "fail", _, _, false) := {"no_suggestion": "no_directive"}

# -- The suggested change (OD-8): the class's Fix directive, as Fix would place it ---------------------------------------
# A bound directive sets attributes on the failing resource; a standalone one adds a resource beside it, its identity
# taken from the failing resource where the plan shows it. A value that is a placeholder (`<NAME>`) makes the
# suggestion incomplete. `lines` is the rendered HCL, the same layout as Fix's Terraform snippet
# (control-plane/modules/fix_snippets/render.py), and is left out when a change has a shape it does not render.

suggestion(cid, r, _) := s if {
	tf := class_doc(cid).terraform
	tf.target.kind == "bound"
	tf.bound_resource_type == r.resource_type
	changes := plain_changes(tf.changes)
	s := object.union(
		{"target": "this_resource", "changes": changes, "complete": complete(changes)},
		lines_part(body_lines(changes, 1)),
	)
}

suggestion(cid, r, project) := s if {
	tf := class_doc(cid).terraform
	tf.target.kind == "standalone"
	tf.bound_resource_type == r.resource_type
	identity := [{"op": "set", "path": [i.attribute], "value": identity_value(i, project)} | some i in tf.target.identity]
	changes := array.concat(identity, plain_changes(tf.changes))
	s := object.union(
		{
			"target": "new_resource",
			"resource_type": tf.target.resource_type,
			"changes": changes,
			"complete": complete(changes),
		},
		lines_part(standalone_lines(tf.target, identity, plain_changes(tf.changes))),
	)
}

plain_changes(changes) := [plain_change(c) | some c in changes] if {
	count(changes) > 0
	every c in changes {
		c.op == "set"
	}
}

plain_change(c) := {"op": "set", "path": c.path, "key": c.key, "value": c.value} if {
	is_string(c.key)
} else := {"op": "set", "path": c.path, "value": c.value}

identity_value(i, project) := project if {
	i.group == "project"
	is_string(project)
} else := concat("", ["<", upper(i.group), ">"])

placeholder(v) if {
	is_string(v)
	regex.match(`^<[A-Z0-9_]+>$`, v)
}

complete(changes) := false if {
	some c in changes
	placeholder(c.value)
} else := true

lines_part(lines) := {"lines": lines} if {
	count(lines) > 0
	count(lines) <= 200
} else := {}

# -- HCL rendering (attributes, one map level, one block level) ----------------------------------------------------------

indent(depth) := concat("", ["  " | some _ in numbers.range(1, depth)]) if depth > 0

indent(depth) := "" if depth <= 0

spaces(n) := concat("", [" " | some _ in numbers.range(1, n)]) if n > 0

spaces(n) := "" if n <= 0

ljust(s, width) := concat("", [s, spaces(width - count(s))])

hcl_string(s) := concat("", ["\"", replace(replace(s, "\\", "\\\\"), "\"", "\\\""), "\""])

hcl_value(v) := "true" if {
	v == true
} else := "false" if {
	v == false
} else := hcl_string(v) if {
	is_string(v)
} else := format_int(v, 10) if {
	is_number(v)
	v == floor(v)
} else := concat("", ["[", concat(", ", [hcl_string(x) | some x in v]), "]"]) if {
	is_array(v)
}

# `not is_string(c.key)` would fail on an absent key (opa evaluates the reference before the negation), so the
# negation goes through this rule.
has_key(c) if is_string(c.key)

is_map_change(c) if {
	count(c.path) == 1
	is_string(c.key)
}

is_attribute_change(c) if {
	count(c.path) == 1
	not has_key(c)
}

is_block_change(c) if {
	count(c.path) == 2
	not has_key(c)
}

renderable(changes) if {
	every c in changes {
		renderable_change(c)
	}
}

renderable_change(c) if is_map_change(c)

renderable_change(c) if is_attribute_change(c)

renderable_change(c) if is_block_change(c)

attribute_lines(entries, depth) := lines if {
	count(entries) > 0
	width := max([count(e.name) | some e in entries])
	lines := [sprintf("%s%s = %s", [indent(depth), ljust(e.name, width), hcl_value(e.value)]) | some e in entries]
} else := []

# Map and block names in the order the directive first names them.
map_names(changes) := [n |
	some i, c in changes
	is_map_change(c)
	n := c.path[0]
	i == min([j | some j, other in changes; is_map_change(other); other.path[0] == n])
]

block_names(changes) := [n |
	some i, c in changes
	is_block_change(c)
	n := c.path[0]
	i == min([j | some j, other in changes; is_block_change(other); other.path[0] == n])
]

map_lines(changes, name, depth) := lines if {
	entries := [{"key": hcl_string(c.key), "value": c.value} |
		some c in changes
		is_map_change(c)
		c.path[0] == name
	]
	width := max([count(e.key) | some e in entries])
	inner := [sprintf("%s%s = %s", [indent(depth + 1), ljust(e.key, width), hcl_value(e.value)]) | some e in entries]
	opening := [
		sprintf("%s%s = {", [indent(depth), name]),
		sprintf("%s# ... keep your other %s entries ...", [indent(depth + 1), name]),
	]
	lines := array.concat(array.concat(opening, inner), [sprintf("%s}", [indent(depth)])])
}

block_lines(changes, name, depth) := lines if {
	entries := [{"name": c.path[1], "value": c.value} |
		some c in changes
		is_block_change(c)
		c.path[0] == name
	]
	opening := [sprintf("%s%s {", [indent(depth), name])]
	lines := array.concat(array.concat(opening, attribute_lines(entries, depth + 1)), [sprintf("%s}", [indent(depth)])])
}

body_lines(changes, depth) := lines if {
	renderable(changes)
	attributes := [{"name": c.path[0], "value": c.value} | some c in changes; is_attribute_change(c)]
	attribute_sections := [attribute_lines(attributes, depth) | count(attributes) > 0]
	map_sections := [map_lines(changes, n, depth) | some n in map_names(changes)]
	block_sections := [block_lines(changes, n, depth) | some n in block_names(changes)]
	sections := array.concat(array.concat(attribute_sections, map_sections), block_sections)
	lines := [line | some i, section in sections; some line in separated(i, section)]
} else := []

separated(i, section) := section if i == 0

separated(i, section) := array.concat([""], section) if i > 0

standalone_lines(target, identity, changes) := lines if {
	body := body_lines(changes, 1)
	count(body) > 0
	entries := [{"name": c.path[0], "value": c.value} | some c in identity]
	opening := [sprintf("resource %s %s {", [hcl_string(target.resource_type), hcl_string(target.name)])]
	head := array.concat(opening, attribute_lines(entries, 1))
	lines := array.concat(array.concat(head, array.concat([""], body)), ["}"])
} else := []
