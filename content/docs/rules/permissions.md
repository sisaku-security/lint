---
title: "Permissions Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Permissions Rule Overview

This rule enforces the principle of least privilege by validating permission settings in GitHub Actions workflows. It ensures that workflows explicitly define appropriate permission scopes and use only valid permission values, reducing the attack surface and preventing accidental privilege escalation.

#### Key Features:

- **Top-Level Permissions Validation**: Ensures workflow-level permissions use only `read-all`, `write-all`, or `none`
- **Job-Level Permissions Validation**: Validates job-specific permission scopes
- **Scope Validation**: Checks that only valid permission scopes are used
- **Value Validation**: Ensures permission values are limited to `read`, `write`, or `none`
- **Explicit Configuration**: Encourages explicit permission declarations over defaults

### Security Impact

**Severity: Warning (CodeQL canonical: `Security severity: 5.0`, `Severity: warning`, `Precision: high`)**

The rule itself currently emits no in-message severity token; the canonical severity above is inherited from the upstream CodeQL query (`actions-missing-workflow-permissions`).

Misconfigured permissions in GitHub Actions workflows can lead to serious security issues:

1. **Privilege Escalation**: Overly broad permissions grant unnecessary access to repository resources
2. **Token Abuse**: Workflows with `write-all` permissions can modify code, releases, and deployments
3. **Secret Exposure Risk**: Excessive permissions increase the attack surface for credential theft
4. **Supply Chain Attacks**: Write access to packages or releases can enable supply chain compromise
5. **Compliance Violations**: Overly permissive workflows may violate security policies

This aligns with **OWASP CI/CD Security Risk CICD-SEC-02: Inadequate Identity and Access Management** and **CWE-275: Permission Issues** (the canonical CWE tag from the upstream CodeQL query `actions-missing-workflow-permissions`).

> Note: For organizations or repositories created before February 2023, the default `GITHUB_TOKEN` permissions are set to read-write. Newer repositories default to a more restricted scope. Explicit `permissions:` declarations are still the safest baseline regardless of repo age.

### Understanding GitHub Actions Permissions

GitHub Actions uses the `GITHUB_TOKEN` to authenticate workflow runs. By default, this token has broad permissions, but you should explicitly limit them using the `permissions:` key.

#### Permission Scopes

Available permission scopes include:

| Scope | Controls Access To |
|-------|-------------------|
| `actions` | GitHub Actions runs and artifacts |
| `artifact-metadata` | Artifact metadata (newer scope, validated by rule) |
| `attestations` | Build provenance attestations |
| `checks` | Check runs and check suites |
| `contents` | Repository contents (code, releases) |
| `deployments` | Deployment statuses |
| `discussions` | GitHub Discussions |
| `id-token` | OIDC token generation |
| `issues` | Issues and issue comments |
| `models` | GitHub-hosted ML models |
| `packages` | GitHub Packages |
| `pages` | GitHub Pages |
| `pull-requests` | Pull requests and comments |
| `repository-projects` | Classic repository projects |
| `security-events` | Code scanning alerts |
| `statuses` | Commit statuses |

#### Permission Values

Each scope accepts three values:

- **`read`**: Read-only access (recommended default)
- **`write`**: Read and write access (use sparingly)
- **`none`**: No access (explicitly deny)

#### Top-Level Permission Values

At the workflow or job level, you can set blanket permissions. Only the following three values are accepted by GitHub Actions at the top-level position:

- **`read-all`**: Read access to all scopes (safer default)
- **`write-all`**: Write access to all scopes (avoid if possible)
- **`{}` (empty object)**: Explicitly deny all permissions (use this when you want a workflow with no API access)

> Note: `permissions: none` is **not** valid at the top level — the runner rejects it at the parse stage. To deny all permissions, use `permissions: {}`. (GitHub's official wording: "You can use the following syntax to disable permissions for all of the available permissions: `permissions: {}`".)

### Example Vulnerable Workflow

Common permission misconfigurations:

```yaml
name: CI Build

on: [push, pull_request]

# PROBLEM: Using invalid permission value
permissions: write  # ❌ Invalid - should be "write-all", "read-all", or "none"

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      # PROBLEM: Invalid scope name
      check: write  # ❌ Should be "checks" not "check"

      # PROBLEM: Invalid permission value
      issues: readable  # ❌ Should be "read", "write", or "none"

      # PROBLEM: Invalid value for scope
      contents: write-all  # ❌ Scopes only accept "read", "write", or "none"

    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

### What the Rule Detects

The Permissions Rule validates:

1. **Invalid Top-Level Permissions**:
   ```yaml
   permissions: write  # ❌ Error - use "write-all", "read-all", or "none"
   ```

2. **Unknown Permission Scopes**:
   ```yaml
   permissions:
     check: write  # ❌ Error - "check" is not a valid scope (should be "checks")
     repo: read    # ❌ Error - "repo" is not a valid scope
   ```

3. **Invalid Scope Values**:
   ```yaml
   permissions:
     issues: readable   # ❌ Error - should be "read", "write", or "none"
     contents: full     # ❌ Error - should be "read", "write", or "none"
   ```

4. **Missing Permissions** (in some contexts):
   - Workflows without explicit permissions may inherit overly broad defaults
   - The missing-permissions warning is **suppressed** when the workflow is invoked via `workflow_call` (reusable workflow), since permissions are inherited from the caller (see *Reusable Workflows* below).
   - The missing-permissions warning is also **suppressed** when the workflow-level `permissions:` block is omitted *and* every job declares its own explicit `permissions:` block — in that case, the workflow-level omission is a no-op and not reported.

### Safe Patterns

#### Pattern 1: Minimal Permissions (Recommended)

Explicitly grant only the permissions your workflow needs:

```yaml
name: CI Build

on: [push, pull_request]

# Grant read-only access by default
permissions:
  contents: read      # Can checkout code
  pull-requests: read # Can read PR metadata

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
```

#### Pattern 2: Deny All Permissions

For workflows that don't need any GitHub API access:

```yaml
name: Static Analysis

on: [push]

# Deny all permissions
permissions: {}

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint
```

#### Pattern 3: Job-Level Permissions

Grant permissions only to jobs that need them:

```yaml
name: Build and Release

on:
  push:
    tags: ['v*']

# Workflow-level: read-only by default
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    # Build job uses default (read-only)
    steps:
      - uses: actions/checkout@v4
      - run: npm run build

  release:
    needs: build
    runs-on: ubuntu-latest
    # Release job needs write access
    permissions:
      contents: write    # Can create releases
      packages: write    # Can publish packages
    steps:
      - uses: actions/checkout@v4
      - uses: actions/create-release@v1
```

#### Pattern 4: OIDC Token Generation

For deployments using OpenID Connect:

```yaml
name: Deploy to AWS

on:
  push:
    branches: [main]

permissions:
  id-token: write  # Generate OIDC token
  contents: read   # Checkout code

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
          aws-region: us-east-1
      - run: aws s3 sync ./dist s3://my-bucket/
```

### Best Practices

#### 1. **Start with Minimal Permissions**

Begin with read-only or no permissions, then add only what's needed:

```yaml
# Good: Explicit minimal permissions
permissions:
  contents: read
  pull-requests: read

# Bad: Overly broad permissions
permissions: write-all
```

#### 2. **Use Job-Level Permissions**

Isolate privileged operations to specific jobs:

```yaml
jobs:
  test:
    permissions:
      contents: read  # Testing doesn't need write access
    steps: [...]

  deploy:
    permissions:
      contents: write  # Only deployment needs write access
    steps: [...]
```

#### 3. **Avoid `write-all` Except When Necessary**

The `write-all` permission is rarely needed:

```yaml
# Bad: Unnecessarily broad
permissions: write-all

# Good: Specific permissions
permissions:
  contents: write
  pull-requests: write
```

#### 4. **Document Why Write Access is Needed**

Add comments explaining privileged permissions:

```yaml
permissions:
  contents: write  # Required to push generated documentation
  packages: write  # Required to publish Docker images
```

#### 5. **Review Inherited Permissions**

If you don't set `permissions:`, workflows inherit broad defaults. Always be explicit:

```yaml
# Without this, workflow inherits write-all by default (dangerous!)
permissions:
  contents: read
```

### Common Mistakes

#### Mistake 1: Using Invalid Values

```yaml
# ❌ Wrong
permissions: write

# ✅ Correct
permissions: write-all
# or better:
permissions:
  contents: write
```

#### Mistake 2: Typos in Scope Names

```yaml
# ❌ Wrong
permissions:
  check: write      # "check" doesn't exist
  pull-request: read # Should be plural

# ✅ Correct
permissions:
  checks: write
  pull-requests: read
```

#### Mistake 3: Using Invalid Scope Values

```yaml
# ❌ Wrong
permissions:
  contents: full
  issues: readonly

# ✅ Correct
permissions:
  contents: write
  issues: read
```

### Auto-Fix

When a workflow has no top-level `permissions:` block and the missing-permissions warning is not suppressed, sisakulint can inject an empty placeholder via `-fix on`:

```yaml
permissions:
  # TODO: Review and add required permissions. Auto-fix sets empty (no permissions) for safety.
  {}
```

Behavior:

- The injected block is `permissions: {}` (deny-all by default) accompanied by a `TODO` head comment instructing the user to review and add the minimum required scopes.
- Insertion position is deterministic: immediately after the `on:` block, or — if no `on:` is present — after `name:` / `run-name:`, or finally at the top of the workflow file.
- The auto-fix never overwrites an existing `permissions:` block; it only injects when one is absent and the suppression rules above do not apply.

### Detection Example

Running sisakulint on a misconfigured workflow:

```bash
$ sisakulint .github/workflows/ci.yml

.github/workflows/ci.yml:4:14: "write" is invalid for permission for all the scopes. [permissions]
     4 👈|permissions: write

.github/workflows/ci.yml:11:7: unknown permission scope "check". all available permission scopes are "actions", "artifact-metadata", "attestations", "checks", "contents", "deployments", "discussions", "id-token", "issues", "models", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses" [permissions]
     11 👈|      check: write

.github/workflows/ci.yml:13:15: The value "readable" is not a valid permission for the scope "issues". Only 'read', 'write', or 'none' are acceptable values. [permissions]
     13 👈|      issues: readable

.github/workflows/ci.yml:14:17: The value "write-all" is not a valid permission for the scope "contents". Only 'read', 'write', or 'none' are acceptable values. [permissions]
     14 👈|      contents: write-all
```

### Relationship to Other Rules

Proper permissions are foundational to other security rules:

- **[envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}})**: Critical severity because privileged workflows have write permissions
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: More dangerous in workflows with elevated permissions
- **[untrustedcheckout]({{< ref "untrustedcheckout.md" >}})**: Checking out untrusted code with write permissions is especially risky

**Defense-in-depth strategy:**
1. Use minimal permissions (this rule)
2. Validate untrusted input (envvar-injection, code-injection rules)
3. Review privileged operations (untrustedcheckout rule)

### Real-World Impact

Misconfigured permissions have led to:

- **Repository takeovers**: Workflows with `contents: write` can push malicious code
- **Package poisoning**: Workflows with `packages: write` can publish compromised artifacts
- **Secret theft**: Broad permissions increase the attack surface for credential exfiltration
- **CI/CD compromise**: Write access enables persistent backdoors in automation

### Advanced Scenarios

#### Conditional Permissions

You cannot conditionally set permissions, so use separate jobs:

```yaml
jobs:
  check:
    if: github.event_name == 'pull_request'
    permissions:
      contents: read
    steps: [...]

  deploy:
    if: github.event_name == 'push'
    permissions:
      contents: write
    steps: [...]
```

#### Reusable Workflows

Permissions in reusable workflows are inherited from the caller. The Permissions rule **does not flag** a missing top-level `permissions:` block in workflows whose trigger is `workflow_call` (i.e. reusable workflows themselves), because the effective permissions are decided by the caller, not the callee.

```yaml
# caller.yml
permissions:
  contents: read

jobs:
  call-reusable:
    uses: ./reusable.yml
    # Inherits "contents: read" from workflow level
```

### References

- [CodeQL: `actions-missing-workflow-permissions`](https://codeql.github.com/codeql-query-help/actions/actions-missing-workflow-permissions/) — upstream canonical query (sisakulint deliberately ports this; CWE-275, `Security severity: 5.0`).
- [GitHub Docs: Automatic Token Authentication](https://docs.github.com/en/actions/security-guides/automatic-token-authentication)
- [GitHub Docs: Permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
- [GitHub Security: Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP: CI/CD Security Risk CICD-SEC-02](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [CWE-275: Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

### Testing

To test this rule:

```bash
# Detect permission misconfigurations
sisakulint .github/workflows/*.yml

# Ignore other rules to focus on permissions
sisakulint -ignore code-injection-critical .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore permissions
```

However, disabling this rule is **strongly discouraged** as proper permission configuration is fundamental to GitHub Actions security.
