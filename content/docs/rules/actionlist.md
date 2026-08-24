---
title: "Action List Rule"
weight: 1
---

This page describes sisakulint [v0.3.6](https://github.com/sisaku-security/sisakulint/releases/tag/v0.3.6).

## Overview

Checks the actions referenced by `uses:` against a list in the configuration file. A reference
matching none of the patterns in the list is reported.

**Nothing is reported without configuration.** The rule is registered unconditionally and runs on
every workflow the tool manages to parse; with no `action-list` entries it allows every
reference, so it reports nothing. It begins reporting once `action-list` holds at least one
pattern.

The configuration is read from `.github/sisakulint.yaml`, or from `.github/sisakulint.yml` if
the first is absent, or from the path given to `-config-file` — which need not be under
`.github`, or even inside the repository.

## Detection Scope

When `action-list` holds one or more patterns, every step's `uses:` value in a job is matched
against all of them, and **a reference matching none of them produces one finding**.

Pattern matching works as follows.

- `*` is replaced by "any string"; every other character is treated literally, producing a
  regular expression.
- The match is anchored against **the whole `uses:` value**. What follows `@` is part of the
  match too.

Not examined:

- **`run:` steps.** They reference no action, so they are out of scope.
- **The contents of an action.** Only whether the reference matches the list. Trustworthiness is
  not judged.
- **Reusable workflows called with `jobs.<job_id>.uses`.** This rule walks the steps of a job.
  A workflow called from the job itself is not matched against the list, and the actions used
  inside that workflow are not reached either.

References beginning with `docker://` and local actions inside the repository are `uses:` values
too, so they are in scope.

This rule emits no severity. A finding carries the file position, the message, and the rule name only.

## Remediation

1. **To keep using the action, review it and add the narrowest pattern that covers it.** Look at
   the provider, at what the step passes the action, and at what the job's `permissions:` grant
   it; then write a pattern for that reference and no more. A full-length commit SHA matched
   exactly is the narrowest form, and it rejects every other ref (see Security Background). Once
   the reference matches, the finding clears — what the list records is the pattern, not the
   review.

2. **Do not forget the `@`.** The pattern `actions/checkout` does **not** match
   `actions/checkout@v4`. To match including the version, write `actions/checkout@*`.

   ```yaml
   action-list:
     - actions/checkout@*        # matches
     - actions/checkout          # does not match (what follows @ is left over)
   ```

3. **To stop using it, remove the step or replace it with an action that is on the list.**

Deleting the list, or emptying it, also clears findings, but that turns the rule off rather than
allowing the reference.

## Example Workflow the Rule Detects

The example is a pair: a workflow and a configuration.

`.github/sisakulint.yaml`:

```yaml
action-list:
  - actions/checkout@*
  - actions/setup-node@*
```

`.github/workflows/ci.yaml`:

```yaml
name: CI

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      # not covered by any pattern in action-list
      - name: Publish coverage
        uses: unknown-org/coverage-uploader@v1
```

## Example Output

```bash
.github/workflows/ci.yaml:16:9: action 'unknown-org/coverage-uploader@v1' is not in the whitelist in step 'Publish coverage' [action-list]
       16 👈|      - name: Publish coverage
```

Only this rule's finding is shown; other rules report on the same run. A third line under each
finding (a column pointer, all spaces) is omitted here.

## Example Workflow the Rule Does Not Detect

The same workflow with the referenced action replaced by one on the list, and a pattern added to
the list. This rule reports nothing.

`.github/sisakulint.yaml`:

```yaml
action-list:
  - actions/checkout@*
  - actions/setup-node@*
  - codecov/codecov-action@*
```

`.github/workflows/ci.yaml`:

```yaml
name: CI

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      # covered by a pattern in action-list
      - name: Publish coverage
        uses: codecov/codecov-action@18283e04ce6e62d37312384ff67231eb8fd56d24
```

## Security Impact

An action referenced by `uses:` runs inside that job. It runs under the job's `GITHUB_TOKEN`
permissions, and it receives whatever secrets, inputs, and environment variables the step hands
it. What a given action can reach therefore depends on the job's `permissions:` and on what the
step passes, not on the reference alone.

What this rule provides is **a practice of limiting references to an explicit list**. A
reference matching none of the patterns produces a finding, so where the exit status gates a
merge, adding that reference has to be dealt with explicitly. How much that catches depends on
how wide the patterns are: `actions/*` admits an unreviewed `actions/<anything>@...`, and `*`
admits everything.

Being on the list does not mean the action is safe. The list is a set of allowed patterns, and
`sisakulint -generate-action-list` will even build one from the references already in the
repository's workflows — so it is not a record of what has been inspected, nor of what has been
seen. A pattern can therefore cover a reference that no one has looked at, and the tool cannot
tell the two apart.

## Security Background

What a reference resolves to is not fixed by the reference alone. A tag can be repointed after it
is written, so the same `@v1` can come to mean different contents.

Supply-chain management therefore has two axes: **whose actions you use** (this rule) and
**whether you pin the version** (`commit-sha`). The two overlap only where a pattern names the
version: `actions/*` leaves the version free, while `actions/checkout@<full sha>` as a pattern
rejects any other ref. A provider-only pattern cannot prevent a version being swapped, and
pinning alone cannot prevent unknown providers being added.

## Attack Scenario

1. A change that adds a dependency also adds one `uses:` line for a new action
2. Neither the provider nor the contents of that action have been reviewed
3. When the job runs, the action executes within that job's permissions and credentials
4. Without a list, that one line passes among the other changes

With a list, step 4 produces a finding **when the new reference matches none of the patterns**,
making the decision to add it explicit. A pattern such as `actions/*` — or `*` — already covers
the new reference, and nothing is reported.

## Related Rules

- [commit-sha]({{< ref "commitsharule.md" >}}): pin an action's version to a commit SHA
- [known-vulnerable-actions]({{< ref "knownvulnerableactions.md" >}}): detect known vulnerable actions
- [archived-uses]({{< ref "archiveduses.md" >}}): detect references to archived actions

## Rule Specific Guide

### There is no denying side

The configuration has no key for a deny list, so no action can be named here for rejection.
That limit is sisakulint's: GitHub's own repository and organization settings can allow or block
selected actions and reusable workflows, which is a separate enforcement layer with its own
scope (see References). What happens when you write a deny list into this file depends on where
you write it, and the two cases differ:

- A **top-level** `blacklist:` key is an unknown key. It is ignored, the run proceeds, and the
  entry has no effect.
- `action-list:` carrying a **nested** `whitelist:` / `blacklist:` map is **rejected**.
  `action-list` is read as a list of strings, so a map there fails the whole configuration: the
  run exits 3 without linting anything.

`sisakulint -init` emits the second shape, under the comment "You can define a whitelist (only
these actions are allowed) or a blacklist (these actions are blocked)". Following that comment
does not leave the deny list inert — it stops the tool.

### Watch where the configuration file goes

`sisakulint -init` writes the configuration to `.github/action.yaml`, but repository
auto-discovery reads `.github/sisakulint.yaml`, falling back to `.github/sisakulint.yml`.
Leaving the file produced by `-init` where it lands does not make this rule work. Pointing
`-config-file` at it does not either: it ends with a bare tab character, which fails to parse,
and once that is removed its nested `action-list` fails on the type (see above). Both exit 3.

`sisakulint -generate-action-list` is the working way in. It reads the workflows already in
`.github/workflows/`, writes `.github/sisakulint.yaml` — the path auto-discovery reads — and the
rule works from there. Note what it writes: one entry per reference, each ending in `@*`, so the
generated list names providers and leaves every version free. Narrow the entries you care about
afterwards (see Remediation).

Writing the file by hand works too, in this form.

```yaml
action-list:
  - actions/checkout@*
```

### The configuration file is part of the control

A pattern such as `*` covers every reference, so a finding can be cleared by editing the
configuration rather than the workflow — and one change can do both.

The rule reads the configuration it is given and does not compare it with an earlier state, so it
reports nothing about that edit. Whether the file is reviewed, and whether the list stays
non-empty and free of a catch-all pattern, is settled outside sisakulint — by who may change that
file, and by whatever runs alongside the lint.

### Writing patterns

| pattern | matches `actions/checkout@<sha>`? |
|---|:---:|
| `actions/checkout@*` | yes |
| `actions/*` | yes |
| `*` | yes (allows everything — effectively disabled) |

### Where the allowlist recommendation comes from

The briefing StepSecurity gave at Black Hat USA 2025 on the `tj-actions/changed-files` compromise
ends with four recommendations, and one of them is "Enforce an Action Allowlist". This rule is a
check of that kind. What makes curation a control at all is scale: "With over 25,000 actions in
the GitHub Marketplace, curation is essential."

What that briefing reports about the incident:

- The action was "actively used in over 23,000 public repositories, including those belonging to
  GitHub, Hugging Face, HashiCorp, Meta, and Microsoft".
- The attackers used "imposter commits", which live in a fork rather than in the target
  repository. Since "release tags can point to these ghost commits", the code ran while the
  repository's own history stayed clean.
- The payload "dumped the memory of the Runner.Worker process", which holds the secrets a run is
  given, and those secrets left through the build log.

A list would not by itself have stopped this one. The reference written in the workflow never
changed. The tag it named was repointed underneath it, and a pattern naming the provider matches
the compromised reference exactly as it matches the honest one. That is the other axis, and it is
another of the same four recommendations: "Organizations using commit SHAs instead of mutable
tags were not affected by this incident" (see Security Background, and `commit-sha`).

OWASP's Top 10 CI/CD Security Risks counts using a marketplace action as granting a third party
access to the pipeline. Under CICD-SEC-08 the risk covers "installing a plugin from the build
system’s marketplace (e.g. actions in Github Actions, Orbs in CircleCI)", and its recommendations
are governance controls over the whole lifecycle of such a dependency (approval, visibility over
ongoing usage, deprovisioning). A list held in one repository covers part of the first.

## References

- [GitHub: Using third-party actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
- [GitHub: Managing GitHub Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [OWASP: CICD-SEC-03 - Dependency Chain Abuse](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse)
- [OWASP: CICD-SEC-08 - Ungoverned Usage of 3rd Party Services](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services)
- [StepSecurity: our Black Hat 2025 presentation on the tj-actions supply chain breach](https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach)
- [Rule source (`v0.3.6`)](https://github.com/sisaku-security/sisakulint/blob/v0.3.6/pkg/core/actionlist.go)
