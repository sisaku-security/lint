---
title: "Environment Variable Injection Rule"
weight: 10
aliases:
  - /docs/rules/envvarinjectioncritical/
  - /docs/rules/envvarinjectionmedium/
---

This page describes sisakulint [v0.3.6](https://github.com/sisaku-security/sisakulint/releases/tag/v0.3.6).

## Overview

If you arrived here from a finding tagged `[envvar-injection-critical]` or
`[envvar-injection-medium]`, this page describes both. They are one check with one
implementation, and the suffix is a severity label the check picks from the workflow's
triggers. It is not a reading of this particular finding: what the check leaves uninspected is
listed under Detection Scope.

The check looks for an untrusted GitHub expression on a line of a `run:` script that also matches
its pattern for appending to `$GITHUB_ENV`. Matching that pattern is not the same as appending —
see Detection Scope. A value that does reach `$GITHUB_ENV` becomes an environment variable for the
following steps of the same job, so a value carrying a newline can define variables nobody wrote.

## Detection Scope

The rule reads every `run:` script in a job line by line. One regular expression selects which
lines are candidates, and the line is never parsed as shell. Selecting the line is not the whole
test: the expression must also parse and be classified as untrusted, the step's `env:` can drop
the finding, and the workflow's triggers decide which of the two names it carries.

- **Detects**: a single physical line on which both of these appear:
  1. a match for `` >>\s*["']?\$\{?GITHUB_ENV\}?["']? `` — so `>> $GITHUB_ENV`,
     `>> "$GITHUB_ENV"`, `>> '$GITHUB_ENV'`, `>> ${GITHUB_ENV}` and `>>   "${GITHUB_ENV}"` all
     qualify; and
  2. an untrusted expression spelled **exactly** `${{ expr }}` (one space each side) or
     `${{expr}}` (none). `${{ expr}}`, `${{expr }}` and `${{  expr  }}` are not recognised.

- **The two only have to share a line.** Because nothing is parsed, the rule cannot tell a
  redirect from text that resembles one, and it does not check what the redirect targets:

  | line | reported | what is actually happening |
  |---|:---:|---|
  | `# echo "T=${{ … }}" >> $GITHUB_ENV` | yes | a shell comment; nothing runs |
  | `echo "T=${{ … }}" >> $GITHUB_ENV_BACKUP` | yes | a different file — the pattern has no end anchor |
  | `echo "T=${{ … }} was written >> $GITHUB_ENV"` | yes | the text is inside quotes, not a redirect |
  | `echo "T=${{ … }}" > $GITHUB_ENV` | no | an overwrite, which GitHub honours the same way |
  | `echo "T=${{ … }}" >> $env:GITHUB_ENV` | no | the PowerShell spelling |

- **No state carries between lines.** A heredoc body, a line under `exec >> "$GITHUB_ENV"`, a
  `{ … } >> "$GITHUB_ENV"` block, and a line continued with `\` all report nothing, because the
  expression and the append are not on one line.
- **The same finding can repeat.** Expressions are collected from the whole script, and every
  matching line is then tested against all of them **by text**: a line reports once for each
  collected expression whose text appears on that line. Two identical expressions on two
  appending lines give four. A matching line that holds no expression adds nothing. An expression
  written on a line that is not an append counts only when the same text also appears on an
  appending line — a *different* expression that sits only off the append is not reported.
- **The step's `env:` suppresses it.** If the same expression appears in any `env:` entry of the
  step, the finding is dropped — whether or not the script uses that variable. A job-level or
  workflow-level `env:` does not suppress it.
- **Which rule name you get**: decided per workflow. If the workflow's `on:` includes a
  privileged trigger, findings are reported as `envvar-injection-critical`; otherwise as
  `envvar-injection-medium`. The privileged set is `pull_request_target`, `workflow_run`,
  `issue_comment`, `issues`, `discussion_comment` and `pull_request_review`. **The medium side is
  the complement, not a list** — any workflow without one of those six is on it, including
  `workflow_call`, `schedule` and `workflow_dispatch`. The two are mutually exclusive: a workflow
  with both `pull_request` and `pull_request_target` reports only the critical name. A job-level
  `if:` does not narrow this.
- **Does not detect**: which variable is being written — `LD_PRELOAD=` and `SAFE_NAME=` are the
  same one finding; a value reaching `$GITHUB_ENV` through a shell variable; a `uses:` step, so
  `actions/github-script` calling `core.exportVariable` is invisible; the job's `permissions`;
  whether the value was sanitized.

`code-injection` looks at the same expression, so the two findings often arrive together. How
often is not something this page measures. They are not tied to one another, and they judge the
trigger differently: `code-injection` reads a
job-level `if:` and this rule does not, so under `on: [pull_request_target, push]` with
`if: github.event_name == 'push'` the same line carries `envvar-injection-critical` and
`code-injection-medium` at once.

## Remediation

Pass the untrusted value through the step's `env:` **and reference the shell variable**, so the
expression never reaches the script text. That much is settled. For a value that may contain
newlines the two published recommendations point in different directions, and the choice is
yours to make.

**Write the value to a file.** This is GitHub's own instruction for a value you cannot bound:
*"If the value is completely arbitrary then you shouldn't use this format. Write the value to a
file instead"* (see References). Nothing in the value can close a record early, because there is
no record. What it costs is the interface — the steps that follow read a path rather than an
environment variable, so every consumer of the value changes with it.

**Or keep it in `$GITHUB_ENV` behind a heredoc whose delimiter is generated when the job runs.**
CodeQL recommends this for multi-line values: *"Use unique identifiers when defining multi line
environment variables"*. Later steps read the variable as they already do:

```yaml
- name: Export PR body
  env:
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    delim="EOF_$(uuidgen)"
    {
      printf '%s\n' "PR_BODY<<${delim}"
      printf '%s\n' "$PR_BODY"
      printf '%s\n' "${delim}"
    } >> "$GITHUB_ENV"
```

`printf` rather than `echo`: a value that is exactly `-n` is read by bash's `echo` as an option,
and the line writes nothing at all.

**What you carry by choosing the heredoc is the delimiter.** GitHub's rule is that it *"won't
occur on a line of its own within the value"*. A delimiter written as a literal in a document is
one an attacker can put on its own line in a PR body, closing the record early and turning the
rest into further variables. Generating it when the job runs takes that guess away, because the
value is fixed before the delimiter exists. It does not bound the value: if that residue is not
acceptable for your input, take the file form above.

Note what actually silences the rule: naming the expression in the step's `env:` is enough on its
own. `env: {PR_TITLE: ${{ … }}}` with `run: echo "PR_TITLE=$PR_TITLE" >> "$GITHUB_ENV"` reports
nothing and is still injectable, because a newline in `$PR_TITLE` still writes a second variable.
The rewrite above is worth doing because of the heredoc, not because the rule stopped reporting.

## Auto-fix

`-fix on` rewrites the step: it adds a step-level `env:` entry whose name is generated from the
expression path, and replaces the expression with `$(echo "$VAR" | tr -d '\n')`.

```diff
-      - run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV
+      - run: echo "TITLE=$(echo "$PR_TITLE" | tr -d '\n')" >> $GITHUB_ENV
+        env:
+          PR_TITLE: ${{ github.event.pull_request.title }}
```

The replacement is applied to the whole script, not only to the lines the pattern matched: a line
that merely prints the same expression is rewritten too. When `code-injection` fires on the same
step its fixer runs first and leaves those other lines as a bare `$VAR`, so what you get depends
on which rules fired.

`tr -d '\n'` removes newlines, which is what closes the "one value, two variables" shape; it does
not remove `\r`, and it destroys a value that is meant to be multi-line. It is not the heredoc
form recommended above.

Two shapes come out of `-fix` without that sanitising step at all.

- **A value tainted through another job.** `needs.<job>.outputs.<name>` carrying an untrusted
  value is reported by this rule, but the report is added in a pass that registers no fixer of
  its own. `code-injection` does register one for the same expression, so the rewrite that
  actually lands is that rule's: the expression moves into `env:` and the line becomes a bare
  `$VAR`, with no `tr -d` and no heredoc. Because the expression has left the script, running
  the linter again reports nothing — the run is green and the newline still writes a second
  variable.
- **A generated name that is already taken.** The name comes from the expression path, and if
  the step already defines it, the fixer keeps the existing entry and rewrites the line to read
  from it. A step holding `PR_TITLE: fixed-existing-value` ends up appending that fixed value
  rather than the title, so the injection shape is gone and so is the intended value.

`-fix dry-run` prints the rewritten file to stdout and leaves it on disk unchanged.

## Example Workflow the Rule Detects

A privileged trigger, so findings carry `envvar-injection-critical`:

```yaml
name: pr-label
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  label:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
      - run: ./scripts/label.sh
```

## Example Output

```bash
.github/workflows/w.yml:12:14: environment variable injection (critical): "github.event.pull_request.title" is potentially untrusted and written to $GITHUB_ENV in a workflow with privileged triggers. This can allow attackers to inject additional environment variables. Use heredoc syntax with unique delimiters or sanitize the input with 'tr -d '\n''. See https://sisaku-security.github.io/lint/docs/rules/envvarinjectioncritical/ [envvar-injection-critical]
       12 👈|      - run: echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
```

Changing only `pull_request_target:` to `pull_request:` in that workflow changes the finding in
four places — the word in the message, the clause naming the trigger, the slug in the URL, and
the rule name in brackets:

```bash
.github/workflows/w.yml:12:14: environment variable injection (medium): "github.event.pull_request.title" is potentially untrusted and written to $GITHUB_ENV. This can allow attackers to inject additional environment variables. Use heredoc syntax with unique delimiters or sanitize the input with 'tr -d '\n''. See https://sisaku-security.github.io/lint/docs/rules/envvarinjectionmedium/ [envvar-injection-medium]
       12 👈|      - run: echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
```

Both runs report two findings and exit 1: this rule, and `code-injection` on the same
expression at column 29. A third line under each finding (a column pointer, all spaces) is
omitted here. Note that this rule's column is 14 — the start of the `run:` scalar, not the
position of the expression.

## Example Workflow the Rule Does Not Detect

The same workflow with the value passed through `env:` and appended with a heredoc.

```yaml
name: pr-label
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  label:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - env:
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          delim="EOF_$(uuidgen)"
          {
            printf '%s\n' "PR_BODY<<${delim}"
            printf '%s\n' "$PR_BODY"
            printf '%s\n' "${delim}"
          } >> "$GITHUB_ENV"
      - run: ./scripts/label.sh
```

This produces no findings at all and exits with status 0. Two separate things make it quiet: the
expression is no longer in the script, and the append is inside a block whose redirect is on
another line — the second would silence the rule even if the first were untrue.

Three things are being conflated when that is read as "fixed", and they do different work. Moving
the expression into `env:` keeps it out of the script text, which is the script-injection
mitigation. The heredoc with a delimiter generated per run is what lets a multi-line value be
written as one value. Putting the redirect on another line does nothing but silence this rule.
A workflow that keeps the expression inline and merely adds an unused `env:` entry is equally
quiet and not equally safe.

## Security Impact

A value written to `$GITHUB_ENV` is available to the following steps of the same job. The step
that writes it cannot read it, and it does not reach earlier steps, other jobs, or the rest of
the workflow.

**The impact is conditional.** A finding means only that an untrusted expression shares a line
with something matching the append pattern. Whether a later step reads the variable, and what it
does with it, is not examined. The platform bounds only a narrow set of names. Measured on
`ubuntu-latest`: writing `NODE_OPTIONS` is refused with a build error
(`Can't store NODE_OPTIONS output parameter using '$GITHUB_ENV' command`), and a runner-provided
default such as `RUNNER_OS` keeps its own value at run time. Everything else takes: `PATH` can be
prepended, and even `GITHUB_TOKEN` can be shadowed — it is not a runner default (it arrives as a
secret), so a following step reads an attacker's value in its place. This is not a page about
what an injected variable can do; the point is that the platform's refusals cover far less than
their reputation, so the finding should not be read as bounded by them.

## Attack Scenario

The strongest use of this injection needs two things: the `$GITHUB_ENV` write to set a variable,
and something else to give that variable a target. On a privileged trigger:

1. A step under `pull_request_target` writes an untrusted field to `$GITHUB_ENV`, e.g.
   `echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"`
2. The attacker's PR title carries a newline, so the value defines a second variable that names
   an interpreter hook — `BASH_ENV=/path/to/attacker/file` or `LD_PRELOAD=/path/to/attacker.so`.
   Both take effect on the steps that follow (measured on `ubuntu-latest`): `BASH_ENV` is sourced
   by every later `bash` step, and `LD_PRELOAD`'s constructor runs in every process those steps
   spawn
3. The file the hook points at has to exist. On `pull_request_target` the default checkout is the
   base repository, not the PR, so this step is where a second weakness is needed — a workflow
   that checks out the PR head (see `untrusted-checkout` under Related Rules) puts attacker files
   on disk, and a writable path under `$GITHUB_WORKSPACE` or `$RUNNER_TEMP` is enough
4. From the next step on, the hook runs with the job's permissions and secrets

Without step 3 the injection still defines variables the later steps read as data; the
interpreter-hook path is what turns it into code execution, and it is not something a single
`$GITHUB_ENV` write achieves alone.

## Related Rules

- [code-injection-critical]({{< ref "codeinjectioncritical.md" >}}): the same untrusted
  expression used directly in a `run:` script, rather than written to `$GITHUB_ENV`
- [code-injection-medium]({{< ref "codeinjectionmedium.md" >}}): the normal-trigger counterpart
- [untrusted-checkout]({{< ref "untrustedcheckout.md" >}}): checking out the PR head under a
  privileged trigger — the second weakness that supplies the file in the scenario above
- [permissions]({{< ref "permissions.md" >}}): keeping the token's scope minimal, which bounds
  what the injected environment can reach

## Rule Specific Guide

### The line is the whole test

Other rules in this repository do parse the shell. `secret-in-log` walks a bash abstract syntax tree (AST) to
find writes to `$GITHUB_ENV`, which is why it sees heredocs and `>` overwrites. This rule does not use
that machinery, and the table in Detection Scope is the consequence: it reports lines that only
look like an append, and misses appends that do not fit on one line.

If you are triaging a finding, read the line rather than the message. If you are looking for this
class of problem across a repository, this rule alone will not find all of it.

### Silencing it

`sisakulint -ignore '^envvar-injection-critical$'` drops this rule's findings from the output.
The flag takes a regular expression matched against the **rule name** — the flag's help text says
it matches error messages, but the implementation matches the rule name (sisakulint#591), so
`-ignore 'environment variable injection'` does not work.

This changes nothing about the workflow. The report is what goes away, not the condition it
reports.

## References

- [GitHub: Workflow commands — setting an environment variable](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands?tool=bash)
  — the value is available to subsequent steps of the same job but not to the step that sets it;
  the *default* environment variables are fixed; `NODE_OPTIONS` specifically cannot be set this
  way; and a heredoc delimiter must not appear on its own line inside the value
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [CodeQL: Environment variable injection (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-envvar-injection-critical/)
- [CodeQL: Environment variable injection (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-envvar-injection-medium/)
- [CWE-77: Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP CICD-SEC-04: Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- [Rule implementation](https://github.com/sisaku-security/sisakulint/blob/dea1408b296a54edc30206ee844daf5ea185b79e/pkg/core/envvarinjection.go)
- [Trigger analysis](https://github.com/sisaku-security/sisakulint/blob/dea1408b296a54edc30206ee844daf5ea185b79e/pkg/core/job_trigger_analyzer.go): the job-level `if:` that `code-injection`
  reads and this rule does not
- [Linter](https://github.com/sisaku-security/sisakulint/blob/dea1408b296a54edc30206ee844daf5ea185b79e/pkg/core/linter.go#L900-L950): fixers are collected in rule order, and `-ignore` is matched
  against the rule name rather than the message
- [`secret-in-log` implementation](https://github.com/sisaku-security/sisakulint/blob/dea1408b296a54edc30206ee844daf5ea185b79e/pkg/core/secretinlog.go): the bash abstract syntax tree it walks
- [Command-line flags](https://github.com/sisaku-security/sisakulint/blob/dea1408b296a54edc30206ee844daf5ea185b79e/pkg/core/command.go#L248): the `-ignore` flag, whose help text says it matches error
  messages
