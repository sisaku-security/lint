---
title: "Untrusted Checkout TOCTOU Critical Rule"
weight: 1
---

### Untrusted Checkout TOCTOU Critical Rule Overview

This rule detects **Time-of-Check to Time-of-Use (TOCTOU)** vulnerabilities in GitHub Actions workflows. It identifies scenarios where label-based approval mechanisms can be bypassed due to using mutable branch references instead of immutable commit SHAs.

**Security Severity: 9.3 (Critical)**

**Vulnerable Example:**

```yaml
name: CI
on:
  pull_request_target:
    types: [labeled]

jobs:
  test:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}  # DANGEROUS: Mutable reference!
      - run: npm ci && npm test
```

**Detection Output:**

```bash
vulnerable.yaml:11:9: TOCTOU vulnerability: checkout uses mutable reference with 'labeled' event type on 'pull_request_target' trigger (line 4). An attacker can modify code after label approval. The checked-out code may differ from what was reviewed. Use immutable '${{ github.event.pull_request.head.sha }}' instead of mutable branch references. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckouttoctoucritical/ [untrusted-checkout-toctou/critical]
     11 👈|      - uses: actions/checkout@v4
```

The finding is anchored at the `actions/checkout` step, and the line number cited in the message points at the `labeled` event type declaration (`types: [labeled]` on line 4 in this example).

### Security Background

#### What is TOCTOU?

TOCTOU (Time-of-Check to Time-of-Use) is a race condition vulnerability where the state of a resource changes between when it's checked and when it's used.

In the context of GitHub Actions:
1. **Time-of-Check**: A maintainer reviews the PR code and applies a "safe-to-test" label
2. **Time-of-Use**: The workflow checks out and runs the code
3. **Attack Window**: Between labeling and execution, an attacker can push malicious commits

#### Attack Scenario

```
1. Attacker opens PR with benign code
2. Maintainer reviews code, approves, adds "safe-to-test" label
3. Workflow triggers due to 'labeled' event
4. ATTACK WINDOW: Attacker force-pushes malicious code
5. Workflow checks out malicious code using mutable branch ref
6. Malicious code executes with repository secrets
```

#### Why is this Critical?

| Risk Factor | Impact |
|-------------|--------|
| **Secrets Access** | Malicious code runs with full access to repository secrets |
| **Write Permissions** | `pull_request_target` has write access to the repository |
| **Bypass Review** | Attack occurs after code review is complete |
| **Supply Chain** | Can inject malicious code into releases |

#### OWASP and CWE Mapping

- **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition
- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Detection Logic

#### Trigger Coverage

The rule scans workflows triggered by **`pull_request_target` or `pull_request`** when the trigger declares the `labeled` event type:

```yaml
on:
  pull_request_target:   # detected
    types: [labeled]
```

```yaml
on:
  pull_request:          # ALSO detected
    types: [labeled]
```

`pull_request` (non-target) is covered because the same TOCTOU window exists there: the code that runs can differ from the code that was reviewed when the label was applied, even though the token is less privileged. The `types: [labeled]` declaration on the trigger is a **precondition** — workflows without it are not analyzed by this rule, even if individual jobs check for label events in their `if:` conditions.

#### What Gets Detected

Within a labeled-triggered workflow, the rule flags `actions/checkout` steps whose `ref:` contains a mutable reference:

1. **PR head branch reference**
   ```yaml
   ref: ${{ github.event.pull_request.head.ref }}
   ```

2. **Branch name reference**
   ```yaml
   ref: ${{ github.head_ref }}
   ```

These are the **only two patterns detected** (matched as substrings of the `ref:` value). Other expressions — e.g. `${{ github.ref }}` or `${{ github.event.pull_request.head.label }}` — are **not** flagged by this rule.

#### Trigger Narrowing via Job-Level `if:`

The rule does not assume that a labeled workflow trigger means every job runs on it. When computing which jobs to analyze, it honors job-level `if:` conditions that constrain **`github.event_name`** — e.g. in a workflow triggered by both `pull_request_target: types: [labeled]` and `push`, a job guarded by `if: github.event_name == 'push'` can never run on the labeled trigger and is therefore not flagged.

Note the narrowing operates on **event names only**. Conditions on the action type, such as `if: github.event.action == 'opened'`, are **not** interpreted — a job carrying such a condition is still analyzed (conservatively treated as reachable from the labeled trigger).

#### Safe Patterns (NOT Detected)

Using immutable commit SHA:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}  # Immutable!
```

Using `github.sha` for merged commit:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.sha }}
```

#### Relationship to the `untrusted-checkout` Rule

This rule and the sibling [`untrusted-checkout`](../untrustedcheckout/) rule divide the untrusted-checkout problem space:

- **This rule (`untrusted-checkout-toctou/critical`)** is scoped to the **label-approval TOCTOU window**: it fires only when a `labeled` event type gates the workflow *and* the checkout uses one of the two mutable-ref patterns above. The attack it models is "code changed between label approval and execution".
- **`untrusted-checkout`** covers the general case: checking out PR-controlled code under a privileged trigger (`pull_request_target`, `issue_comment`, `workflow_run`, `workflow_call`), regardless of label gating, with a broader set of unsafe ref patterns.

Both rules can fire on the same checkout step — a labeled `pull_request_target` workflow that checks out `github.head_ref` matches both scopes. Their auto-fixes differ (this rule rewrites the ref to `head.sha`; `untrusted-checkout` rewrites it to `github.sha`), so when applying `-fix`, review which rewrite ran.

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will replace mutable refs with immutable SHA references.

**Example:**

Before auto-fix:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.ref }}
```

After running `sisakulint -fix on`:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
```

> ⚠️ **The replacement is a substring rewrite, not a whole-value rewrite.** Only the mutable expression inside the `ref:` value is swapped for `${{ github.event.pull_request.head.sha }}`; surrounding literal text is preserved. If your `ref:` mixes literals with the expression — e.g. `ref: prefix-${{ github.head_ref }}-suffix` — the result is `prefix-${{ github.event.pull_request.head.sha }}-suffix`, which is a valid YAML string but almost certainly not an existing git ref, so the checkout will fail at runtime. Preview with `-fix dry-run` before applying if your `ref:` values are not pure expressions.

### Remediation Steps

1. **Use immutable commit SHA**
   ```yaml
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.event.pull_request.head.sha }}
   ```

2. **Add approval requirement in job condition**
   ```yaml
   jobs:
     test:
       if: |
         contains(github.event.pull_request.labels.*.name, 'safe-to-test') &&
         github.event.action == 'labeled'
   ```

3. **Consider using environment protection rules**
   - Require approval before running in protected environments
   - Use deployment environments with required reviewers

### Best Practices

1. **Always use SHA for external PR code**
   ```yaml
   ref: ${{ github.event.pull_request.head.sha }}
   ```

2. **Minimize privileged workflow scope**
   - Only checkout what's necessary
   - Run untrusted code in isolated jobs

3. **Use workflow_run for separation**
   ```yaml
   # First workflow (unprivileged)
   on: pull_request
   # Runs tests without secrets

   # Second workflow (privileged)
   on: workflow_run
   # Only runs after first workflow succeeds
   ```

4. **Implement additional approval checks**
   - Require multiple labels or approvals
   - Use GitHub's deployment environments

### References

- [CodeQL: Untrusted Checkout TOCTOU](https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-toctou-critical/)
- [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
