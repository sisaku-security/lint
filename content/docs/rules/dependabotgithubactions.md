---
title: "Dependabot GitHub Actions Rule"
weight: 7
bookToc: true
---

### Dependabot GitHub Actions Rule Overview

This rule checks whether a repository has Dependabot configured with the `github-actions` ecosystem when unpinned actions are detected. Without Dependabot, major version updates (e.g., v3 → v4) for GitHub Actions won't be automated, leaving workflows exposed to known vulnerabilities in outdated action versions.

#### Key Features:

- **Missing Configuration Detection**: Detects when `.github/dependabot.yaml` does not exist
- **Missing Ecosystem Detection**: Detects when `dependabot.yaml` exists but lacks the `github-actions` package ecosystem
- **Auto-fix Support**: Automatically creates or updates the Dependabot configuration file
- **Smart Skip**: Does not trigger when all actions are already pinned to full 40-character commit SHAs

### Security Impact

**Severity: Warning (4/10)**

Missing Dependabot configuration for GitHub Actions creates a supply chain management gap:

1. **Outdated Actions**: Without automated updates, workflows continue using action versions with known vulnerabilities
2. **Manual Update Burden**: Teams must manually track and update action versions, which is error-prone
3. **Missing Security Patches**: Critical security fixes in actions may go unnoticed without automated PR creation
4. **Version Drift**: Over time, pinned versions become increasingly outdated, accumulating security debt

This aligns with OWASP CI/CD Security Risk **CICD-SEC-03: Dependency Chain Abuse** and **CICD-SEC-08: Ungoverned Usage of 3rd Party Services**.

### Two Detection Scenarios

#### Scenario 1: No dependabot.yaml Exists

When a workflow uses unpinned actions (e.g., `actions/checkout@v4`) and no `.github/dependabot.yaml` or `.github/dependabot.yml` file exists:

```
dependabot.yaml does not exist. Without Dependabot, major version updates
(e.g., v3 -> v4) for GitHub Actions won't be automated. Create
.github/dependabot.yaml with github-actions ecosystem.
```

#### Scenario 2: Missing github-actions Ecosystem

When a workflow uses unpinned actions and `dependabot.yaml` exists but only configures other ecosystems (e.g., npm, pip):

```
dependabot.yaml exists but github-actions ecosystem is not configured.
Without it, major version updates (e.g., v3 -> v4) for GitHub Actions
won't be automated.
```

### Example: Triggering the Rule

**Workflow with unpinned actions:**
```yaml
# .github/workflows/ci.yml
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # unpinned (tag, not SHA)
      - uses: actions/setup-node@v4        # unpinned
      - run: npm test
```

**Incomplete Dependabot config (missing github-actions):**
```yaml
# .github/dependabot.yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
  # github-actions ecosystem is missing!
```

### No Violation Cases

The rule does NOT trigger when:

- **All actions are SHA-pinned**: If every action uses a full 40-character commit SHA, Dependabot is not required
  ```yaml
  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4
  ```
- **Local actions**: References starting with `./` are skipped
- **Docker actions**: References starting with `docker://` are skipped
- **Dependabot properly configured**: The `github-actions` ecosystem is already present

### Auto-Fix Support

The rule provides automatic fixes for both scenarios:

**Scenario 1 — Creates new `.github/dependabot.yaml`:**
```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

**Scenario 2 — Appends `github-actions` ecosystem to existing file:**
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
  # Auto-added by sisakulint:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

```bash
# Preview changes
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

### Why Dependabot for GitHub Actions Matters

GitHub Actions dependencies are often overlooked in dependency management strategies. While teams commonly configure Dependabot for npm, pip, or Go modules, the `github-actions` ecosystem is frequently missing:

1. **Actions Are Dependencies Too**: Third-party actions are executable code with the same risks as library dependencies
2. **Version Tags Are Mutable**: Unlike package registry versions, Git tags can be moved (see commit-sha rule)
3. **Automated PRs**: Dependabot creates PRs for action updates, enabling review before merge
4. **Security Advisories**: Dependabot alerts on known vulnerabilities in actions

### Related Rules

- **[commit-sha]({{< ref "commitSHARule.md" >}})**: Enforces full commit SHA pinning for actions
- **[known-vulnerable-actions]({{< ref "knownvulnerableactions.md" >}})**: Detects actions with known vulnerabilities
- **[archived-uses]({{< ref "archiveduses.md" >}})**: Detects usage of archived/deprecated actions
- **[action-list]({{< ref "actionlist.md" >}})**: Action allowlist/blocklist enforcement

### References

- [GitHub Docs: Configuring Dependabot version updates](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates)
- [GitHub Docs: Keeping your actions up to date with Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot)
- [OWASP: CICD-SEC-03 Dependency Chain Abuse](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse)
- [OWASP: CICD-SEC-08 Ungoverned Usage of 3rd Party Services](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services)

### Testing

```bash
# Detect missing Dependabot configuration
sisakulint .github/workflows/ci.yaml

# Apply auto-fix to create/update dependabot.yaml
sisakulint -fix on .github/workflows/ci.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore dependabot-github-actions
```
