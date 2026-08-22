---
title: "Self-Hosted Runners Rule"
weight: 1
---

This page describes sisakulint [v0.3.6](https://github.com/sisaku-security/sisakulint/releases/tag/v0.3.6).

## Overview

`self-hosted-runner` detects jobs configured to run on a self-hosted runner. Self-hosted runners keep state between
jobs, so using one in a workflow whose contents can be influenced from outside creates a path
where what a previous run left behind is picked up by the next.

This rule looks at `runs-on`, and at `strategy.matrix` when `runs-on` is a matrix expression.
Neither who can start the workflow nor whether the runner is ephemeral enters the judgement.

## Detection Scope

A job is reported when `runs-on` matches any of the following. Cases 1 to 3 produce one finding
per job; case 4 produces one per matching matrix key, so a job can carry several.

1. **The label list contains `self-hosted`.** Case-insensitive. Other labels alongside it make
   no difference (`[self-hosted, ephemeral]` is included).
2. **`group` is non-empty.** Runner groups conventionally contain self-hosted runners, so this
   is reported with a different message that names the group.
3. **`runs-on` is a scalar, contains no expression, and equals `self-hosted`.**
4. **`runs-on` is an expression, and some matrix key whose name appears in it has a value
   containing `self-hosted`.** Array values are examined element by element. The key name is
   matched as a substring of the expression, so a key named `run` matches
   `${{ matrix.runner }}` — a job whose `runner` values are all GitHub-hosted is reported when
   an unrelated key named `run` happens to hold `self-hosted`.

Not examined:

- **`if:` conditions.** A job is reported even when a condition would prevent it from running.
- **The trigger.** A workflow with only `push` is still reported.
- **Whether the repository is public or private.** That cannot be determined from the workflow file.
- **Additional labels such as `ephemeral`.** If `self-hosted` is present, it is reported.
- **A matrix that is itself an expression**, and **a referenced key whose value is an expression.**
  Those keys are skipped.
- **Expressions other than `matrix.`.** `${{ inputs.runner }}` and `${{ vars.RUNNER }}` are not examined.

This rule emits no severity. A finding carries the file position, the message, and the rule name only.

## Remediation

1. **Switch to a GitHub-hosted runner.** Setting `runs-on: ubuntu-latest` or similar clears the
   finding. GitHub-hosted runners are destroyed after each job, so no state persists.

2. **Adding `if:` or extra labels to silence the finding does not work.** This rule examines
   neither (see Detection Scope). `[self-hosted, ephemeral]` and
   `if: github.repository_owner == '...'` are both reported the same way.

3. **If self-hosted is intended, suppress it in the tool rather than in the workflow.**
   `sisakulint -ignore <regexp>` drops findings whose **rule name** matches — the flag's help
   text says it matches error messages, but the implementation matches the rule name
   (sisakulint#591). For cases 1 to 3 nothing about how the job is written will silence the
   finding. Case 4 is the exception: renaming a matrix key so it is no longer a substring of the
   `runs-on` expression removes the finding, which is a consequence of the matching being on
   spelling rather than on the value actually used.

Note that the `self-hosted-runner.labels` setting in the configuration file is not used by this
rule (see Rule Specific Guide).

## Example Workflow the Rule Detects

```yaml
name: Build

on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    # VULNERABLE: a self-hosted runner is reachable from a trigger that
    # outside contributors can fire.
    runs-on: self-hosted
    timeout-minutes: 30
    permissions:
      contents: read
    steps:
      - name: Run tests
        run: make test
```

## Example Output

```bash
.github/workflows/build.yaml:11:14: job "build" uses self-hosted runner (direct label specification). Self-hosted runners are dangerous in public repositories because they can persist state between workflow runs and allow arbitrary code execution from pull requests. Consider using GitHub-hosted runners or ephemeral self-hosted runners. See https://sisaku-security.github.io/lint/docs/rules/selfhostedrunners/ [self-hosted-runner]
       11 👈|    runs-on: self-hosted
```

The renderer prints a third line under the finding (a column pointer, all spaces) that is
omitted here. Nothing else is reported for this workflow — `self-hosted-runner` is the only rule
that fires on it.

## Example Workflow the Rule Does Not Detect

The same workflow with only `runs-on` changed. This rule reports nothing.

```yaml
name: Build

on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    # SAFE: GitHub-hosted runners are destroyed after every job, so nothing
    # persists between runs.
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read
    steps:
      - name: Run tests
        run: make test
```

## Security Impact

Self-hosted runners are not ephemeral by default. When a job ends, the filesystem, processes,
and cached credentials remain, and the next job inherits them. When a workflow whose contents
an outside contributor can influence runs on such a runner, two things follow.

- **Carry-over into later jobs.** Files written or executables installed by an attacker remain,
  and another workflow's build uses them.
- **Reach into the runner host.** A job is an ordinary process on the runner, so it operates
  within whatever network reachability and credentials that host holds.

GitHub itself advises against using self-hosted runners with public repositories (see References).

## Security Background

A GitHub-hosted runner is a fresh virtual machine per job, destroyed when the job ends. That
destruction is what makes running untrusted code harmless to what follows.

A self-hosted runner has no such destruction. Making one ephemeral is a separate configuration
and is not the default. "Self-hosted" and "ephemeral" are therefore distinct properties, and
the workflow file cannot tell you the latter. That is why this rule reports on the former alone.

## Attack Scenario

1. An attacker opens a pull request. A workflow started by `pull_request_target` runs on a
   self-hosted runner
2. That workflow does something that depends on the PR's contents (running tests, invoking a
   build script)
3. The attacker's code runs on the runner and writes to the host filesystem
4. Another workflow on the same runner reads or executes what was left behind

There is a job boundary between 3 and 4, but on a self-hosted runner state does not vanish at
that boundary.

## Related Rules

- [untrusted-checkout]({{< ref "untrustedcheckout.md" >}}): detect checkouts of untrusted code
- [dangerous-triggers]({{< ref "dangeroustriggersrulecritical.md" >}}): detect privileged triggers
- [permissions]({{< ref "permissions.md" >}}): narrow the workflow's permissions

## Rule Specific Guide

### `self-hosted-runner.labels` in the configuration file has no effect

The sisakulint configuration file contains this section.

```yaml
self-hosted-runner:
  labels: []
```

The default configuration file describes it as letting sisakulint verify that label settings
are correct, but this value is not used by this rule. It is read only when stringifying the
configuration and when regenerating the configuration file. Listing your own labels here does
not change anything: a job containing `self-hosted` is reported just the same.

### There are three message variants

Cases 1 and 3 of Detection Scope share a message (containing `direct label specification`),
case 2 uses a runner-group message, and case 4 uses a matrix message naming the key. The
messages differ, but `-ignore` matches the rule name rather than the message, so one pattern
covers all of them.

## References

- [GitHub: About self-hosted runners — Self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP: CI/CD Top 10 Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Rule source (`v0.3.6`)](https://github.com/sisaku-security/sisakulint/blob/v0.3.6/pkg/core/selfhostedrunnersrule.go)
