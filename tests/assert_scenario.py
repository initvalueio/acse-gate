#!/usr/bin/env python3
"""The fixture CI's assertions, one scenario at a time.

Reads the gate's results (copied from $RUNNER_TEMP/acse-gate after each run), the step outcomes, and what the stand-in
receiver recorded, and checks them against the scenario's expectations. Exits non-zero with every failed expectation
listed.

Usage: assert_scenario.py --scenario <name> --run1 <dir> --outcome1 <success|failure> [--run2 <dir> --outcome2 ...]
                          [--receiver-log <file>] [--variant-root <dir>] [--posting <expected>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICY_REPO = ROOT / "fixtures" / "policy-repo"
SCHEMAS = ROOT / "tests" / "schemas"
SALT = "fixture-salt-not-a-secret-0001"

# scenario: run1 expectations, receiver expectations, run2 expectations
SCENARIOS = {
    "pass": dict(verdict="pass", outcome="success", report="counted", posts=1),
    "enforce-fail": dict(verdict="fail", outcome="failure", report="counted", posts=1,
                         fail=("gcp-storage-uniform-access", "enforce", "module.storage.google_storage_bucket.data",
                               "fixtures/iac/enforce-fail/modules/storage/main.tf", 1),
                         run2=dict(verdict="pass", outcome="success")),
    "observe-fail": dict(verdict="pass", outcome="success", report="counted", posts=1,
                         fail=("gcp-storage-versioning", "observe", "google_storage_bucket.logs",
                               "fixtures/iac/observe-fail/main.tf", 17)),
    "unknown": dict(verdict="pass", outcome="success", report="counted", posts=1, unknown=1),
    "unreachable-fail": dict(verdict="fail", outcome="failure", report="undelivered", posts=0),
    "unreachable-pass": dict(verdict="pass", outcome="success", report="undelivered", posts=0),
    "withdrawn": dict(verdict="pass", outcome="success", report="refused", posts=1, refusal="TEMPLATE_WITHDRAWN"),
    "not-current": dict(verdict="fail", outcome="failure", report="refused", posts=1, refusal="TEMPLATE_NOT_CURRENT"),
    "flaky": dict(verdict="pass", outcome="success", report="counted", posts=2, same_report_id=True),
    "duplicate": dict(verdict="pass", outcome="success", report="counted", posts=2, same_report_id=True),
    "mode-switch": dict(verdict="pass", outcome="success", report="counted", posts=1,
                        run2=dict(verdict="fail", outcome="failure")),
    "salted": dict(verdict="fail", outcome="failure", report="counted", posts=1, salted=True, variant_tree=True),
    # Template 1.1.0: no .github/acse-gate.json, or one that is not gate-config-1.0 (here the retired per-registration
    # audience): the gate still gates, and nothing is sent.
    "no-config": dict(verdict="pass", outcome="success", report="skipped", posts=0,
                      detail="has no .github/acse-gate.json"),
    "bad-config": dict(verdict="pass", outcome="success", report="skipped", posts=0,
                       detail="not a valid gate-config-1.0"),
}

errors: list[str] = []


def expect(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def published_current() -> dict:
    """The newest current release: the one template/ (and so the fixture) carries."""
    releases = load(ROOT / "published-templates.json")["releases"]
    return max((r for r in releases if r["state"] == "current"), key=lambda r: tuple(int(x) for x in r["release"].split(".")))


def class_digest(directory: pathlib.Path, check_id: str) -> str:
    files = sorted((p for p in directory.rglob("*") if p.is_file()), key=lambda p: p.relative_to(directory).as_posix().encode())
    doc = {"algorithm": "acse-class-digest-1", "check_id": check_id,
           "files": [{"path": p.relative_to(directory).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in files]}
    return "sha256:" + hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


ACTION_LINE = re.compile(
    rb"^([ \t]*(?:-[ \t]+)?uses:[ \t]+)[A-Za-z0-9_-]+/[A-Za-z0-9._-]+(/\.github/actions/acse-gate@)[^\s#]+", re.MULTILINE)


def template_digest(root: pathlib.Path) -> str:
    """acse-gate-template-1: the workflow's one action line hashed in its placeholder form."""
    workflow = root / ".github/workflows/acse-gate.yml"
    paths = [workflow] + [p for p in (root / ".github/actions/acse-gate").rglob("*") if p.is_file()]

    def data(p: pathlib.Path) -> bytes:
        b = p.read_bytes()
        return ACTION_LINE.sub(rb"\1__OWNER__/__REPOSITORY__\2__REF__", b) if p == workflow else b
    files = sorted(({"path": p.relative_to(root).as_posix(), "sha256": hashlib.sha256(data(p)).hexdigest()} for p in paths),
                   key=lambda e: e["path"].encode())
    doc = {"format": "acse-gate-template-1", "files": files}
    return "sha256:" + hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_run(name: str, run: pathlib.Path, outcome: str, want: dict, bundle_root: pathlib.Path) -> dict:
    result = load(run / "result.json")
    expect(result["verdict"] == want["verdict"], f"{name}: verdict {result['verdict']}, expected {want['verdict']}")
    expect(outcome == want["outcome"], f"{name}: the step's outcome was {outcome}, expected {want['outcome']}")
    # The job fails exactly on an enforce failure (unknown and observe never fail it).
    finding = load(run / "finding.json")
    jsonschema.validate(finding, load(SCHEMAS / "acse-gate-finding-1.0.schema.json"))
    enforce_fail = any(f["outcome"] == "fail" and f["mode"] == "enforce" for f in finding["findings"])
    expect(enforce_fail == (want["verdict"] == "fail"), f"{name}: the verdict does not follow the enforce failures")
    # Class rows carry the class digest detect computes over the same directory.
    bundle = bundle_root / "bundles" / "main"
    for row in result["rows"]:
        expected = class_digest(bundle / "classes" / row["check_id"], row["check_id"])
        expect(row["class_digest"] == expected, f"{name}: class digest of {row['check_id']} differs from the recipe")
    expect({r["check_id"] for r in result["rows"]} == {c["check_id"] for c in finding["classes"]},
           f"{name}: not every class the bundle ran has a row")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--run1", required=True, type=pathlib.Path)
    parser.add_argument("--outcome1", required=True)
    parser.add_argument("--run2", type=pathlib.Path)
    parser.add_argument("--outcome2")
    parser.add_argument("--receiver-log", type=pathlib.Path, help="what the receiver recorded during the first run only")
    parser.add_argument("--variant-root", type=pathlib.Path)
    parser.add_argument("--posting", default="", help="pull_request: suggestions must have been attempted")
    args = parser.parse_args()
    want = SCENARIOS[args.scenario]
    name = args.scenario
    run1_root = args.variant_root if want.get("salted") else POLICY_REPO
    result = check_run(name, args.run1, args.outcome1, want, run1_root)

    # Annotations: the rule id, the control, the file and line, and the suggestion where there is one.
    annotations = load(args.run1 / "annotations.json")
    if "fail" in want:
        check_id, mode, address, file, line = want["fail"]
        hits = [a for a in annotations if a["check_id"] == check_id and a["address"] == address]
        expect(len(hits) == 1, f"{name}: expected one annotation for {check_id} on {address}")
        if hits:
            a = hits[0]
            expect(a["level"] == ("error" if mode == "enforce" else "warning"), f"{name}: annotation level {a['level']}")
            expect(a["file"] == file and a["line"] == line, f"{name}: annotation at {a['file']}:{a['line']}, expected {file}:{line}")
            expect(check_id in a["title"] and "Controls:" in a["message"]
                   and ("cis-gcp-foundations" in a["message"] or "nist-800-53" in a["message"]),
                   f"{name}: the annotation does not name the rule and its controls")
            expect("Suggested change" in a["message"], f"{name}: the annotation carries no suggestion")
        suggestions = load(args.run1 / "suggestions.json")
        expect(any(s["check_id"] == check_id and s["file"] == file for s in suggestions),
               f"{name}: no one-click suggestion was placed for {check_id}")
    if want.get("unknown"):
        unknowns = [a for a in annotations if a["outcome"] == "unknown"]
        expect(len(unknowns) == want["unknown"] and all(a["level"] == "notice" for a in unknowns),
               f"{name}: unknowns must be notices, never failures")
        expect(sum(r["counts"]["unknown"] for r in result["rows"]) == want["unknown"], f"{name}: unknown count")

    # Suggestions posted as review comments (only where the scenario lets the job's token write).
    posted = load(args.run1 / "suggestions-posted.json") if (args.run1 / "suggestions-posted.json").exists() else {}
    print(f"{name}: suggestions {posted.get('status')} ({posted.get('reason')})")
    if args.posting == "pull_request" and load(args.run1 / "suggestions.json"):
        expect(posted.get("status") in ("posted", "text_only") and "cannot write" not in posted.get("reason", ""),
               f"{name}: suggestions were not attempted as review comments: {posted}")

    # The report: what reached the receiver, and what the job made of the answer.
    outcome = load(args.run1 / "report-outcome.json")
    expect(outcome["state"] == want["report"], f"{name}: report state {outcome['state']}, expected {want['report']}")
    if want.get("refusal"):
        expect(want["refusal"] in outcome["detail"], f"{name}: the refusal reason is not carried: {outcome['detail']}")
    if want.get("detail"):
        expect(want["detail"] in outcome["detail"], f"{name}: the report outcome's detail is {outcome['detail']!r}")
    posts = []
    if args.receiver_log and args.receiver_log.exists():
        posts = [json.loads(line) for line in args.receiver_log.read_text().splitlines() if line.strip()]
    expect(len(posts) == want["posts"], f"{name}: the receiver saw {len(posts)} reports, expected {want['posts']}")
    schema = load(SCHEMAS / "gate-run-report-2.0.schema.json")
    finding = load(args.run1 / "finding.json")
    addresses = {f["address"] for f in finding["findings"]}
    current = published_current()
    # Where the report goes is the policy repository's gate config (template 1.1.0), never a caller's input.
    config_root = args.variant_root if args.variant_root else POLICY_REPO
    config_file = config_root / ".github/acse-gate.json"
    config = load(config_file) if config_file.exists() else {}
    for post in posts[: want["posts"]]:
        body = post["body"]
        expect(post["bearer"], f"{name}: the report came without a bearer token")
        expect(body.get("tenant_id") == config.get("tenant"),
               f"{name}: the report's tenant_id {body.get('tenant_id')!r} is not the config's {config.get('tenant')!r}")
        expect(post.get("aud") == config.get("audience"),
               f"{name}: the OIDC token's audience {post.get('aud')!r} is not the config's {config.get('audience')!r}")
        expect(post["path"] == "/api/gate/v1/reports", f"{name}: posted to {post['path']}")
        expect("oidc" not in body and "keep_names_in_cloud" not in body, f"{name}: the body carries members ACSE writes")
        raw = json.dumps(body)
        for address in addresses:
            expect(address not in raw, f"{name}: the report carries a resource address ({address})")
        for word in ("google_storage_bucket", "acme-", "fixtures/iac", ".tf"):
            expect(word not in raw, f"{name}: the report carries '{word}'")
        # Valid gate-run-report-2.0 once ACSE adds the members it writes from the verified token.
        completed = dict(body, keep_names_in_cloud=False, oidc={
            "issuer": "https://token.actions.githubusercontent.com", "audience": config.get("audience"),
            "repository_id": "1", "workflow_ref_digest": "sha256:" + "0" * 64, "gate_workflow_ref_digest": "sha256:" + "0" * 64,
            "gate_repository_key": "rp-" + "0" * 64, "gate_workflow_commit": "0" * 40, "run_id": "1", "run_attempt": 1,
            "token_id_digest": "sha256:" + "0" * 64, "issued_at": "2026-11-05T00:00:00Z", "expires_at": "2026-11-05T00:05:00Z"})
        try:
            jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(completed)
        except jsonschema.ValidationError as e:
            errors.append(f"{name}: the report is not valid gate-run-report-2.0: {e.message}")
        expect(body["verdict"] == want["verdict"], f"{name}: reported verdict {body['verdict']}")
        expect(body["gate"]["template_release"] == current["release"], f"{name}: template release {body['gate']['template_release']}")
        expect(body["gate"]["template_digest"] == current["template_digest"],
               f"{name}: reported template digest {body['gate']['template_digest']} is not the published {current['template_digest']}")
        expect(body["gate"]["evaluator"] == "opa" and body["gate"]["evaluator_version"] == "1.20.1", f"{name}: evaluator")
        if not want.get("variant_tree"):
            tree = subprocess.run(["git", "rev-parse", "HEAD:fixtures/policy-repo/bundles/main"], cwd=ROOT,
                                  capture_output=True, text=True, check=True).stdout.strip()
            expect(body["bundle"]["tree_id"] == tree, f"{name}: bundle tree id {body['bundle']['tree_id']} is not git's {tree}")
        if want.get("salted"):
            expect(body["address_hashing"] == "salted", f"{name}: address hashing not on")
            failed = [f["address"] for f in finding["findings"] if f["outcome"] == "fail"]
            want_hashes = sorted("ah-" + hashlib.sha256(f"{SALT}\n{a}".encode()).hexdigest() for a in failed)
            got = sorted(h for r in body["classes"] for h in r.get("failed_address_hashes", []))
            expect(got == want_hashes, f"{name}: salted hashes {got} != {want_hashes}")
        else:
            expect(body["address_hashing"] == "off" and not any("failed_address_hashes" in r for r in body["classes"]),
                   f"{name}: hashes without a salt")
    if want.get("same_report_id") and len(posts) >= 2:
        expect(len({p["body"]["report_id"] for p in posts}) == 1, f"{name}: a retry changed the report_id")

    # Second runs: AC-G3 (the suggestion applied) and AC-G4 (a mode switched in bundle.json).
    if "run2" in want:
        if not args.run2:
            errors.append(f"{name}: the second run's results are missing")
        else:
            second_root = args.variant_root if name == "mode-switch" else POLICY_REPO
            check_run(name + " (second run)", args.run2, args.outcome2, want["run2"], second_root)
            if name == "enforce-fail":
                f2 = load(args.run2 / "finding.json")
                fixed = [f for f in f2["findings"] if f["check_id"] == "gcp-storage-uniform-access"
                         and f["address"] == "module.storage.google_storage_bucket.data"]
                expect(len(fixed) == 1 and fixed[0]["outcome"] == "pass", f"{name}: AC-G3, the class does not pass after the fix")
                src = (ROOT / "fixtures/iac/enforce-fail/modules/storage/main.tf").read_text()
                golden = (ROOT / "fixtures/expected/enforce-fail/modules/storage/main.tf").read_text()
                expect(src == golden, f"{name}: AC-G3, the source after the suggestion is not the expected fix")
            if name == "mode-switch":
                variant = args.variant_root
                expect(template_digest(variant) == template_digest(POLICY_REPO) == current["template_digest"],
                       f"{name}: AC-G4, the template changed")
                r1, r2 = load(args.run1 / "result.json"), load(args.run2 / "result.json")
                d1 = {(r["check_id"]): r["class_digest"] for r in r1["rows"]}
                d2 = {(r["check_id"]): r["class_digest"] for r in r2["rows"]}
                expect(d1 == d2, f"{name}: AC-G4, a mode change moved a class digest (parity must hold)")
                expect(r1["bundle_tree_id"] != r2["bundle_tree_id"], f"{name}: the bundle's tree id should change with bundle.json")

    for e in errors:
        print("FAIL:", e)
    if not errors:
        print(f"{name}: all expectations hold")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
