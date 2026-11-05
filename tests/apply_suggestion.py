#!/usr/bin/env python3
"""AC-G3 for the fixture CI: apply the gate's suggested change, then the gate must pass.

Two halves, both from one run's results:
  1. the one-click suggestion (suggestions.json: file, start_line, end_line, replacement), exactly the lines a pull
     request review comment would carry, is applied to the source in the workspace;
  2. the same finding's structured change (finding.json: suggestion.changes) is applied to the plan, standing in for
     re-planning the edited source (the fixture CI runs no Terraform).

Usage: apply_suggestion.py <results-dir> <plan-in> <plan-out> <workspace>
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys


def apply_source(suggestions: list[dict], workspace: pathlib.Path) -> list[str]:
    changed = []
    # Bottom-up per file, so earlier line numbers stay valid.
    for s in sorted(suggestions, key=lambda x: (x["file"], -x["start_line"])):
        path = workspace / s["file"]
        lines = path.read_text(encoding="utf-8").split("\n")
        start, end = s["start_line"] - 1, s["end_line"]
        lines[start:end] = s["replacement"]
        path.write_text("\n".join(lines), encoding="utf-8")
        changed.append(s["file"])
    return changed


def apply_plan(plan: dict, findings: list[dict]) -> dict:
    plan = copy.deepcopy(plan)
    by_address = {rc["address"]: rc for rc in plan.get("resource_changes", [])}
    for f in findings:
        if f.get("outcome") != "fail" or "suggestion" not in f:
            continue
        s = f["suggestion"]
        if s["target"] != "this_resource":
            raise SystemExit("the fixture CI applies this_resource suggestions only: " + f["check_id"])
        change = by_address[f["address"]]["change"]
        after, unknown = change["after"], change.get("after_unknown") or {}
        for c in s["changes"]:
            name = c["path"][0]
            unknown.pop(name, None)
            if len(c["path"]) == 1 and "key" in c:
                after[name] = dict(after.get(name) or {}, **{c["key"]: c["value"]})
            elif len(c["path"]) == 1:
                after[name] = c["value"]
            elif len(c["path"]) == 2:
                block = after.get(name) or [{}]
                block = [dict(block[0], **{c["path"][1]: c["value"]})] + list(block[1:])
                after[name] = block
            else:
                raise SystemExit("unsupported change path: %r" % c["path"])
        change["after_unknown"] = unknown
    return plan


def main(argv: list[str]) -> int:
    results, plan_in, plan_out, workspace = (pathlib.Path(a) for a in argv[1:5])
    suggestions = json.loads((results / "suggestions.json").read_text())
    finding = json.loads((results / "finding.json").read_text())
    if not suggestions:
        raise SystemExit("AC-G3: the run offered no one-click suggestion")
    changed = apply_source(suggestions, workspace)
    plan_out.write_text(json.dumps(apply_plan(json.loads(plan_in.read_text()), finding["findings"]), indent=2) + "\n")
    print("applied to", ", ".join(changed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
