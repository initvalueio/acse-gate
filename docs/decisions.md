# Decisions in the gate template

These are the judgement calls the gate's design leaves to the template. For each one the table gives the default
taken and what it would cost to change it. **D-1 must be settled before the gate can report.**

## D-1 — the template's `uses:` line is per policy repository, so its digest is too (open, blocking reports)

The reusable workflow has to run the composite action from the **same** policy repository, because that is how the
bundle arrives with no credential. GitHub accepts no expression in `uses:`, so the line has to name the repository
literally: `uses: <owner>/<policy-repo>/.github/actions/acse-gate@<branch>`.

So every tenant's copy of `acse-gate.yml` differs in that one line. Under `acse-gate-template-1` as defined (a
sha256 over the exact bytes), **every tenant's template digest is different**, and none of them equals the digest
in `published-templates.json`. A verifier that requires "a digest in the published set" would therefore refuse every
genuine report as `TEMPLATE_NOT_CURRENT`. The gate still gates (AC-G1), but no run would count as *seen*.

What this repository does now:
- `template/` carries the line in one fixed placeholder form:
  `uses: __OWNER__/__REPOSITORY__/.github/actions/acse-gate@__REF__`. It is the only line that differs between
  tenants, and `tests/check_static.py` holds it to exactly one occurrence.
- Release 1.0.0's published digest is computed over `template/` **with the placeholder**.
- The gate reports the digest it computes over the files it actually ran, so it never claims a digest it cannot show.

Options (not decided here):

| | Option | Effect | Cost |
|---|---|---|---|
| a | **Amend `acse-gate-template-1`**: before hashing `.github/workflows/acse-gate.yml`, rewrite its single `uses: <owner>/<repo>/.github/actions/acse-gate@<ref>` line to the placeholder form. Still `sed` + `sha256sum` + `jq` | One digest per release for every tenant. **Release 1.0.0's digest stays valid**, because it is already computed over the placeholder form. The verifier's ACSE-side sync applies the same rewrite | A contract change (recipe, golden vectors, the sync and the verifier). The rewrite is on the line that decides *which* action runs, so the verifier must also check that the owner/repo in that line is the registered policy repository. That holds anyway once the sync reads it at `job_workflow_sha` |
| b | Publish per-tenant digests | No recipe change | The published set becomes per tenant and no longer public-shaped. Against the published set's design |
| c | Keep the exact-bytes digest and have the verifier compare against "the published template rendered for this tenant" | No recipe change | The control plane needs the tenant's owner/repo/branch to render, and the comparison stops being recomputable by anyone with `sha256sum` |

Recommendation: **(a)**. It is the smallest change that keeps the published list public, the same for every tenant,
and recomputable. It needs ACSE's contract owner to decide.

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
