#!/usr/bin/env python3
"""Static checks of the template source, for the fixture CI.

1. The digest recipes in tools/ reproduce ACSE's golden vectors.
2. published-templates.json is valid against acse-gate-published-templates-1.0, its releases and digests are unique,
   and the newest current release is the template in template/ (its digest recomputed here) and the release gate.sh
   names.
3. The fixture policy repository carries the template byte for byte, and the fixture reusable workflow is the template's
   workflow with only the composite action's reference rendered.
4. The pins: OPA by version and checksum, every third-party action by commit.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "template"
errors: list[str] = []


def expect(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def run(*argv: str) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout.strip()


def materialise(files: list[dict], root: pathlib.Path) -> None:
    for f in files:
        path = root / f["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f["content"].encode("utf-8"))


def vectors() -> None:
    for v in json.loads((ROOT / "tests/vectors/template-digest.json").read_text())["vectors"]:
        with tempfile.TemporaryDirectory() as tmp:
            materialise(v["files"], pathlib.Path(tmp))
            got = run("sh", str(ROOT / "tools/template-digest.sh"), tmp)
            expect(got == v["template_digest"], f"template-digest vector {v['name']}: {got} != {v['template_digest']}")
    for v in json.loads((ROOT / "tests/vectors/template-digest.json").read_text())["invalid_vectors"]:
        with tempfile.TemporaryDirectory() as tmp:
            materialise(v["files"], pathlib.Path(tmp))
            refused = subprocess.run(["sh", str(ROOT / "tools/template-digest.sh"), tmp], capture_output=True).returncode
            expect(refused == 2, f"template-digest invalid vector {v['name']}: not refused")
    for v in json.loads((ROOT / "tests/vectors/class-digest.json").read_text())["vectors"]:
        with tempfile.TemporaryDirectory() as tmp:
            materialise(v["files"], pathlib.Path(tmp))
            got = run("sh", str(ROOT / "tools/class-digest.sh"), tmp, v["check_id"])
            expect(got == v["class_digest"], f"class-digest vector {v['name']}: {got} != {v['class_digest']}")


def published() -> None:
    doc = json.loads((ROOT / "published-templates.json").read_text())
    schema = json.loads((ROOT / "tests/schemas/acse-gate-published-templates-1.0.schema.json").read_text())
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(doc)
    releases = doc["releases"]
    expect(len({r["release"] for r in releases}) == len(releases), "a release is listed twice")
    expect(len({r["template_digest"] for r in releases}) == len(releases), "a template digest is listed twice")
    current = [r for r in releases if r["state"] == "current"]
    expect(bool(current), "no current release")
    newest = max(releases, key=lambda r: tuple(int(x) for x in r["release"].split(".")))
    digest = run("sh", str(ROOT / "tools/template-digest.sh"), str(TEMPLATE))
    expect(newest["state"] == "current", f"the newest release {newest['release']} is not current")
    expect(newest["template_digest"] == digest,
           f"template/ has digest {digest}, but release {newest['release']} lists {newest['template_digest']}: "
           "a change to the template is a new release")
    gate_sh = (TEMPLATE / ".github/actions/acse-gate/gate.sh").read_text()
    m = re.search(r'^TEMPLATE_RELEASE="([0-9.]+)"$', gate_sh, re.M)
    expect(bool(m) and m.group(1) == newest["release"], "gate.sh's TEMPLATE_RELEASE is not the newest release")
    print("template digest", digest, "release", newest["release"])


def copies() -> None:
    fixture = ROOT / "fixtures/policy-repo"
    # The fixture policy repository holds the template as ACSE writes it: the action line rendered with a repository and
    # its branch, every other byte the template's. Its digest must still be the published one (the placeholder rule).
    placeholder = "uses: __OWNER__/__REPOSITORY__/.github/actions/acse-gate@__REF__"
    template_wf = (TEMPLATE / ".github/workflows/acse-gate.yml").read_text()
    expect(template_wf.count(placeholder) == 1, "the template must reference its composite action exactly once, by placeholder")
    tenant_wf = template_wf.replace(placeholder, "uses: example-org/acse-policies/.github/actions/acse-gate@main")
    expect((fixture / ".github/workflows/acse-gate.yml").read_text() == tenant_wf,
           "fixtures/policy-repo's acse-gate.yml is not the template rendered for example-org/acse-policies@main")
    expect(run("sh", str(ROOT / "tools/template-digest.sh"), str(fixture)) == run("sh", str(ROOT / "tools/template-digest.sh"), str(TEMPLATE)),
           "the rendered copy's digest is not the template's")
    for rel in sorted(
            p.relative_to(TEMPLATE).as_posix() for p in (TEMPLATE / ".github/actions/acse-gate").rglob("*") if p.is_file()):
        a, b = TEMPLATE / rel, fixture / rel
        expect(b.is_file() and a.read_bytes() == b.read_bytes(), f"fixtures/policy-repo/{rel} is not the template's")
    extra = {p.relative_to(fixture / ".github").as_posix() for p in (fixture / ".github").rglob("*") if p.is_file()} - {
        p.relative_to(TEMPLATE / ".github").as_posix() for p in (TEMPLATE / ".github").rglob("*") if p.is_file()}
    expect(not extra, f"fixtures/policy-repo/.github has files the template does not: {sorted(extra)}")

    rendered = template_wf.replace(placeholder, "uses: ./fixtures/policy-repo/.github/actions/acse-gate")
    fixture_wf = (ROOT / ".github/workflows/fixture-acse-gate.yml").read_text()
    expect(fixture_wf == rendered, ".github/workflows/fixture-acse-gate.yml is not the template's workflow, rendered")


def pins() -> None:
    gate_sh = (TEMPLATE / ".github/actions/acse-gate/gate.sh").read_text()
    expect('OPA_VERSION="1.20.1"' in gate_sh, "OPA is not pinned to 1.20.1")
    expect('OPA_SHA256_LINUX_AMD64="0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f"' in gate_sh,
           "OPA's checksum is not the pinned one")
    for wf in list((ROOT / ".github/workflows").glob("*.yml")) + list(TEMPLATE.rglob("*.yml")):
        for line in wf.read_text().splitlines():
            m = re.match(r"^\s*-?\s*uses:\s*([^\s#]+)", line)
            if not m or m.group(1).startswith("./") or "__OWNER__" in m.group(1):
                continue
            expect(re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)) is not None,
                   f"{wf.relative_to(ROOT)}: {m.group(1)} is not pinned to a commit")


def main() -> int:
    vectors()
    published()
    copies()
    pins()
    for e in errors:
        print("FAIL:", e)
    print("static checks:", "failed" if errors else "all hold")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
