# acse-gate

The ACSE CI gate template. It checks a Terraform plan against your own policy bundle before the change merges. It
uses plain, pinned [OPA](https://www.openpolicyagent.org/) and nothing else, and it needs no credential.

This repository is the **source** of the template and the **list of published releases**. It never runs the gate
itself. ACSE copies the template into your policy repository by pull request, and your infrastructure repositories
call it from there.

## What runs, and where

```
your IaC repository                         your policy repository (acse-policies)
───────────────────                         ──────────────────────────────────────
job: plan                                   .github/workflows/acse-gate.yml      ← the thin reusable workflow
  terraform plan -out tfplan                .github/actions/acse-gate/           ← the composite action it runs
  terraform show -json tfplan > plan.json   .github/acse-gate.json               ← where the verdict goes (generated)
  upload-artifact acse-gate-plan            bundles/current                      ← names the bundle directory
job: acse-gate                              bundles/<name>/bundle.json           ← observe / enforce, per class and label
                                            bundles/<name>/gate/, classes/<id>/  ← the Rego, the same that detect runs
  uses: <org>/acse-policies/.github/workflows/acse-gate.yml@main
```

GitHub fetches the workflow, the action, the config and the bundle together, through the policy repository's
**Actions → General → Access → "Accessible from repositories in the organization"** setting. You turn this on once.
No token, deploy key or App is involved.

The workflow is a shell: one job with one step, the composite action. Everything below happens in the action, so a
new release normally changes only `.github/actions/acse-gate/`.

The gate job:

1. checks out the code under review and downloads the plan the `plan` job uploaded;
2. installs `opa` 1.20.1, verified by its sha256 (or uses `opa-path` if your runner already has that build);
3. evaluates `data.acse.gate.finding` over the plan, with the bundle as data:
   ```
   opa eval --format json --capabilities opa_capabilities.json --input plan.json \
     --data acse_bundle.control:bundles/<name>/bundle.json \
     --data acse_bundle.classes:bundles/<name>/classes \
     --data bundles/<name>/gate [--data acse_bundle.tfvars:tfvars.json] 'data.acse.gate.finding'
   ```
4. finds each failing resource's file and line from the plan's `configuration` (its module calls) and `grep`;
5. annotates the pull request with the rule, the controls it maps to, and the suggested change where the class has
   one. If your job grants `pull-requests: write`, the suggestion is also posted as a one-click review suggestion;
6. reports the **verdict only** to ACSE with the job's OIDC token: per class, counts, modes and digests. No plan,
   addresses, values, file names or code are sent. The tenant, the token's audience and the report URL come from
   `.github/acse-gate.json` in the policy repository (below); without it the gate sends no report;
7. fails the job **only** when a class in `enforce` mode fails.

| Outcome | Annotation | Fails the job |
|---|---|---|
| fail, `enforce` | error | yes |
| fail, `observe` | warning | no |
| unknown (a value known only after apply, or a resource outside the plan) | notice | never |
| ACSE unreachable, or the report refused | warning | never: the verdict stands |
| the gate could not evaluate (no plan, a broken bundle) | error | yes, unless the bundle enforces nothing |

Strictness lives in `bundle.json`, set from ACSE's Policy Studio. Moving a class from observe to enforce changes the
bundle, never a workflow file.

## Calling it from an IaC repository

The plan is made in your own job and handed over as an artifact of the same workflow run. It stays inside your
workflow run and never leaves your runners.

```yaml
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: hashicorp/setup-terraform@v3
      - run: |
          terraform -chdir=infra init
          terraform -chdir=infra plan -out=tfplan
          terraform -chdir=infra show -json tfplan > plan.json
      - uses: actions/upload-artifact@v7
        with: { name: acse-gate-plan, path: plan.json, retention-days: 1 }

  acse-gate:
    needs: plan
    permissions:
      contents: read
      id-token: write          # the verdict-only report; omit to run without reporting
      pull-requests: write     # optional: one-click suggested changes
    uses: <org>/acse-policies/.github/workflows/acse-gate.yml@main
    with:
      working-directory: infra
```

The caller names nothing about your ACSE tenant, so the file is the same in every repository.

| Input | Default | Meaning |
|---|---|---|
| `plan-artifact` | `acse-gate-plan` | Artifact (uploaded earlier in the run) holding the plan JSON |
| `plan-file` | `plan.json` | The plan's path inside the artifact |
| `tfvars-file` | — | Optional variables JSON inside the artifact (only used to name a resource's project) |
| `working-directory` | `.` | The Terraform root the plan was made in, for file and line |
| `runs-on` | `ubuntu-latest` | A Linux x64 runner with `bash`, `jq`, `curl`, `git` and `sha256sum` |

The workflow's `verdict` output is `pass`, `fail` or `error`. For several Terraform roots, upload one plan per root
under its own artifact name and call the gate once per root.

**Why an artifact.** A reusable workflow runs as its own job, so the plan has to cross from your job to the gate's.
An artifact of the same run carries any size of plan. It needs no permission and no secret, and it is deleted with the
run (`retention-days: 1`). A workflow input string has a size limit, and a cache is shared across runs. A plan can
contain sensitive values, so keep the retention short. Anyone who can read the repository's Actions can download an
artifact.

## Where the verdict goes: `.github/acse-gate.json`

The policy repository holds one config file, `.github/acse-gate.json` (ACSE's contract `gate-config-1.0`):

```json
{
  "gate_config_format_version": "1.0",
  "tenant": "<tenant id>",
  "audience": "acse-gate:gta-<32 hex>",
  "report_url": "https://<your ACSE address>/api/gate/v1/reports",
  "generated_from": { "repository": "<org>/acse-setup", "commit": "<sha>", "tenant_yaml_sha256": "sha256:<hex>" }
}
```

Your ACSE setup apply generates it from `config/tenant.yaml` and commits it with your own credentials; ACSE never
proposes it. The audience is one per tenant and is not a secret. The gate reads the file at the commit it runs, asks
GitHub for an OIDC token for that audience, and posts the verdict to that URL. A missing file sends no report (a
notice); a file that is not valid `gate-config-1.0` sends no report (a warning). Either way the verdict stands. The
file is outside the template, so it is outside the template digest.

## The template, releases and digests

- `template/.github/` is copied verbatim into a policy repository. The only exception is the one `uses:` line that
  runs the composite action: `__OWNER__/__REPOSITORY__` and `__REF__` become your policy repository and its branch,
  because GitHub does not accept an expression in `uses:`. Call the gate at that same branch
  (`.../acse-gate.yml@main`). ACSE checks that the line names your policy repository and the ref your workflow
  called, and refuses reports otherwise.
- `published-templates.json` lists every release, with its `acse-gate-template-1` digest and its state: `current`, or
  `withdrawn` with a reason. ACSE accepts reports only from a template whose digest is a release that has not been
  withdrawn. An edited copy still gates your pull requests, but its reports are refused.
- `acse-gate-template-1` is sha256 over the canonical JSON `{format, files: [{path, sha256}]}` of
  `.github/workflows/acse-gate.yml` and every file under `.github/actions/acse-gate/`, sorted by path. The workflow's
  one action line is hashed in its placeholder form, so your rendered copy has the published digest. Recompute it with
  `tools/template-digest.sh <repository root>` (needs `find`, `sort`, `grep`, `sed`, `sha256sum` and `jq`).
- **ACSE never writes the workflow file.** GitHub refuses App pushes under `.github/workflows/`, and ACSE's App does
  not hold the `workflows` permission. ACSE's pull request writes `.github/actions/acse-gate/` only. When a release
  changes `.github/workflows/acse-gate.yml`, ACSE's Prevent board shows "gate workflow <version> available" with the
  new file, its digest and the reason (the table below): informational, never amber. You apply it by your own pull
  request. A release that changes both files is published action first, so a repository with the new action and the
  old workflow is still on a published release (cio-acse-design ADR-0073 Amendment 8, W-3). 1.1.0 is the exception:
  no repository runs 1.0.0 in the field, so its two files are applied together, in one pull request (W-4).
- Each release is a tag `v<release>`. The release workflow publishes the template archive, its digest and the
  published list, each with a build-provenance attestation:
  `gh attestation verify acse-gate-template-<release>.tar.gz --repo initvalueio/acse-gate`.

## Releases

| Release | Workflow file changed | Why |
|---|---|---|
| 1.0.0 | (first release) | The reusable workflow, the composite action and the published set |
| 1.1.0 | yes | The workflow becomes a one-step shell and drops `audience`, `tenant-id` and `report-url`: where the verdict goes is read from `.github/acse-gate.json` (one audience per tenant), and the checkout and plan download move into the composite action |

## Tests

`.github/workflows/ci.yml` runs the template end to end against a test policy repository (`fixtures/policy-repo`, the
template plus a GCP bundle) and fixture plans (`fixtures/plans`, `fixtures/iac`). It checks:

- pass, enforce-fail, observe-fail and unknown, each with the expected outcome;
- the report: valid `gate-run-report-2.0`, no addresses, the published template digest, and git's tree id for the bundle;
- ACSE unreachable, or refusing the report: the job's outcome is still the verdict;
- retries reuse the same `report_id`;
- applying the suggested change makes the gate pass;
- switching a class to enforce in `bundle.json` changes the outcome with no workflow change;
- salted address hashes;
- the report goes to the tenant, audience and URL in `.github/acse-gate.json`; with no config, or an invalid one (the
  old per-registration audience), the gate still gates and nothing is sent;
- the reusable workflow called as a customer calls it.

## Licence

Apache-2.0.
