# Decisions in the gate template

These are the judgement calls the gate's design leaves to the template. For each one the table gives the default
taken and what it would cost to change it.

## D-1 — the template's `uses:` line names the policy repository (decided 2026-11-05: "Placeholder + strict check")

The reusable workflow has to run the composite action from its **own** policy repository, because that is how the
bundle arrives with no credential. GitHub accepts no expression in `uses:`, so the line names the repository and a ref
literally. Every tenant's copy therefore differs in that one line.

**Decided: placeholder plus a strict check.**
- `template/` carries the line as `uses: __OWNER__/__REPOSITORY__/.github/actions/acse-gate@__REF__`. ACSE renders it
  with the policy repository's owner/name and its branch when it writes the template.
- `acse-gate-template-1` hashes that one line in the placeholder form and every other byte as it is, so every copy of
  a release has the release's digest. The workflow must end with a line feed and hold exactly one such line, or the
  template is invalid. This rule is used by `tools/template-digest.sh`, by `gate.sh` itself, and by ACSE's sync and
  recipes.
- **The strict check is ACSE's verifier's.** The real line must name the registered policy repository, the one
  `job_workflow_ref` names, and the same ref as the signed `job_workflow_ref` (`R`, `refs/heads/R` or `refs/tags/R`).
  A caller must therefore call `acse-gate.yml@<the branch the line names>`, not a commit SHA. Otherwise the reports
  are refused; the gate itself still gates.
- `fixtures/policy-repo` holds a rendered copy (`example-org/acse-policies@main`). The CI checks that its digest, and
  the digest the gate reports, are the published one.

## Other defaults taken

| # | Question | Default | Cost of changing |
|---|---|---|---|
| D-2 | How the plan reaches the gate | An **artifact of the same workflow run** (`plan-artifact`, `plan-file`, optional `tfvars-file`), downloaded in the gate job. Inputs are size-limited; caches cross runs | Low |
| D-3 | Permissions of the gate job | **None declared**. The job inherits the caller's: `contents: read`, `id-token: write` to report, and optionally `pull-requests: write`. If a reusable workflow declares more than its caller grants, the run fails to start | Low |
| D-4 | When the gate cannot evaluate (no plan, a broken bundle, opa failing its checksum) | **Fails the job**, unless the bundle was read and enforces nothing (every class observe): a broken gate must be visible, but an observe-only bundle must never block. Reported as `error` with the closed code | Medium: customers will rely on it |
| D-5 | What a one-click suggestion replaces | The **whole resource block**. Settings the directive changes are removed and the rendered lines added before the closing brace. It is text only when that is unsafe: a map the directive extends, a nested block with other settings, a `dynamic` block, an incomplete value (`<PLACEHOLDER>`), or a resource found only at a remote module's call | Low |
| D-6 | Suggestion review comments | Posted only on a `pull_request` run; skipped when one with the same marker exists; at most 20 per run. A 403 (no `pull-requests: write`) or 422 (lines outside the diff) leaves the annotation's text | Low |
| D-7 | Annotations | Enforce failures, then observe failures, then unknowns, at most 50 per job (GitHub's limit). The job summary lists every one | Low |
| D-8 | The report's retries | 3 attempts, 10 s and 20 s apart, 20 s each, all under two minutes. Each attempt gets a fresh OIDC token and keeps the same `report_id`. 409 `REPORT_DUPLICATE` counts as delivered. Only 429, 5xx or no answer is retried. Any other 4xx is a refusal, shown as a warning with ACSE's code and fixed message | Low |
| D-9 | `http://` report URLs | Refused, except on loopback (`127.0.0.1`, `localhost`), which the fixture CI uses | Low |
| D-10 | The bundle's tree id | Rebuilt from the fetched files in a scratch git index, because GitHub fetches the action as an archive with no `.git`. Object format `sha1` (GitHub's). The fixture CI checks it against `git rev-parse HEAD:<bundle dir>` | Low |
| D-11 | `run.commit` | `GITHUB_SHA`: the commit the job checked out and evaluated (the merge commit on a pull request) | Low |
| D-12 | `job.check_run_id` unavailable on a runner | No report (a warning). The verdict stands | Low |
| D-13 | Runner platform | Linux x64 (the pinned opa build). `opa-path` takes a pre-installed binary with the same checksum, for runners without internet access | Low |
| D-14 | The fixture CI runs no Terraform | Plans are fixtures in `terraform show -json` shape, checked into the repository. AC-G3 is shown in two halves: the suggestion applied to the source equals the expected fix, and the same structured change applied to the plan passes. This avoids provider credentials and any Terraform run in CI | Low |
| D-15 | Schemas in `tests/schemas/` | Validation-only copies of ACSE's contracts, with descriptions removed | Low |

## Template 1.1.0 — the config file and the thin workflow (2026-11-06)

Two decisions of Koushik's, of 2026-11-06, drive this release:

- **GA-1** (cio-acse-design ADR-0085 Amendment 2 §A2.1): one audience per tenant, `acse-gate:gta-<32 hex>`, carried in
  `.github/acse-gate.json` in the policy repository (ACSE's contract `gate-config-1.0`), read by the gate at run time.
  No caller ever contains it, and the template stays byte-identical across tenants under D-1's placeholder rule.
- **Workflow templates are customer-applied.** ACSE's App never holds `workflows`, and GitHub refuses App pushes under
  `.github/workflows/`. ACSE's pull request writes the composite action only; a change to the workflow file is shown
  to the customer as file, digest and a one-line reason (informational, never amber), and the customer applies it. So
  the workflow is kept a thin shell and all logic lives in the composite action.

What 1.1.0 changes:
- the workflow has one job with one step, the composite action. It drops `audience`, `tenant-id` and `report-url`;
- the composite action checks out the code under review and downloads the plan when given `plan-artifact`. It reads
  the tenant, the audience and the report URL from `.github/acse-gate.json` beside it (`$POLICY_ROOT`, fetched by
  GitHub with the action), asks for the OIDC token for that audience and reports there;
- the fixture CI checks that the report's `tenant_id` and the token's `aud` are the config's, and adds the
  `no-config` and `bad-config` scenarios (no report, the verdict stands).

| # | Question | Default | Cost of changing |
|---|---|---|---|
| T-1 | Where the OIDC token request lives | **In the composite action**, not the workflow. The config reaches the runner only with the action (the workflow may name the policy repository once, D-1, and there is no credential to fetch it otherwise), and D-8 asks for a fresh token per attempt | Low |
| T-2 | Checkout and plan download | **Moved into the composite action** (when `plan-artifact` is set), so that a pin bump of `actions/checkout` or `actions/download-artifact` is an action change ACSE can propose, not a workflow change | Low |
| T-3 | The action's path inputs (`plan-json`, `tfvars-json`) | **Kept**, used when `plan-artifact` is empty. A 1.0.0 workflow calling the 1.1.0 action still gates (its `audience`, `tenant-id` and `report-url` become GitHub's "unexpected input" warnings), so the action may land before the workflow. The fixture CI uses them | Low |
| T-4 | A missing or invalid `.github/acse-gate.json` | **No report**, the verdict stands: a notice when missing (GA-23), a warning when it is not `gate-config-1.0` (members, version, patterns). Plain `http://` is admitted on loopback only, as D-9 does, although the contract says https: the fixture's stand-in receiver needs it | Low |
| T-5 | Release 1.0.0 | **Listed, `current`, not withdrawn.** Its callers carry a per-registration audience, which ADR-0085 Am.2 GA-2 refuses once built, so its reports stop counting then regardless; no live registration exists | Low |
| T-6 | The upgrade window (**open: for Koushik**) | `acse-gate-template-1` covers the workflow **and** the action. ACSE's pull request writes the action only, so a policy repository that merges it without the new workflow holds a copy whose digest is no release: reports are refused `TEMPLATE_NOT_CURRENT` and Setup shows "edited" (amber) until the workflow lands. **Default:** ACSE's pull request body and the "gate workflow update available" item ask the customer to add the workflow file to ACSE's pull request branch before merging, so both land in one merge. Applying the 1.1.0 workflow before the action breaks the gate (the 1.0.0 action requires `plan-json`). Alternatives: a template format whose digest covers the action only (a contract change), or the control plane accepting "current action, older workflow" | **Medium**: it decides every future workflow-changing release, and only a contract change avoids the window |
| T-7 | The fixture reusable workflow | The template's workflow, rendered, **plus one checkout step** before the action: a local `./` action is found only in a checked-out workspace. The static check compares it with exactly that | Low |
| T-8 | `released_on` | 2026-11-06, the date of this pull request; the `v1.1.0` tag is pushed after it merges, and the release workflow checks it | Low |
