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
