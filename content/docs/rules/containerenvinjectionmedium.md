---
title: "Container Env Injection Rule (Medium)"
weight: 12
bookToc: true
---

### Container Env Injection Rule (Medium) Overview

This rule detects untrusted input in `container.env` or `services.*.container.env` fields within **normal (non-privileged) workflow triggers**. When an attacker controls these values, they can pollute the container's environment with dangerous variables, potentially affecting build outputs and application behavior.

While the impact is lower than the critical variant (since normal triggers lack write access and secrets by default), environment variable pollution inside containers remains a real risk.

#### Key Features:

- **Normal Trigger Detection**: Identifies dangerous patterns in `pull_request`, `push`, and other non-privileged triggers
- **Container Environment Analysis**: Checks both job-level `container.env` and service container `services.*.container.env`
- **Environment Variable Pollution Detection**: Detects untrusted input that can override variables inside containers
- **Complements Critical Rule**: Only fires on non-privileged triggers, avoiding duplicate warnings with the critical variant

### Security Impact

**Severity: Medium (5/10)**

Container environment variable pollution in normal workflows poses a moderate risk:

1. **`LD_PRELOAD` / `BASH_ENV` Abuse**: Even without secrets access, attackers can hijack processes inside the container via environment-sensitive variables
2. **Build Process Interference**: Poisoned environment values can alter build outputs, test results, and package installations
3. **`PATH` Manipulation**: Overriding `PATH` can make legitimate commands resolve to attacker-controlled binaries
4. **Reduced Blast Radius**: Normal triggers typically lack write access and secrets, limiting the overall impact

This vulnerability is classified as **CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')** and aligns with OWASP CI/CD Security Risk **CICD-SEC-04: Poisoned Pipeline Execution (PPE)**.

### Historical Context: CVE-2022-39321

The original Docker CLI `-e` flag injection (CVE-2022-39321) was **patched in actions/runner v2.299.1**. However, the broader risk remains: attacker-controlled values set through `container.env` are still passed as legitimate environment variables inside the container. See the [critical variant]({{< ref "containerenvinjectioncritical.md" >}}) for a detailed breakdown of what was and wasn't patched.

### Example Vulnerable Workflow

```yaml
name: Vulnerable - Container Env Injection (Medium)

on:
  pull_request:  # Normal trigger (no write access/secrets by default)

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:18
      env:
        # MEDIUM: attacker controls head.ref — value is set inside the container as-is
        BRANCH: ${{ github.event.pull_request.head.ref }}
    steps:
      - run: echo "Testing branch $BRANCH"
```

```yaml
name: Vulnerable - Push Trigger

on:
  push:

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: python:3.11
      env:
        # MEDIUM: commit message is attacker-controlled
        COMMIT_MSG: ${{ github.event.head_commit.message }}
    steps:
      - run: echo "Building: $COMMIT_MSG"
```

### Safe Pattern

Use only trusted, static values or validated inputs in container environment variables:

```yaml
name: Safe - Container Env Injection

on:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:18
      env:
        # SAFE: using trusted values only
        NODE_ENV: test
        COMMIT_SHA: ${{ github.sha }}
    steps:
      - run: echo "Testing commit $COMMIT_SHA"
```

### Detection Details

The rule detects:

1. **Untrusted input in `container.env`**: Job-level container environment variables with attacker-controlled expressions
2. **Untrusted input in `services.*.container.env`**: Service container environment variables with attacker-controlled expressions
3. **Normal (non-privileged) triggers only**: `pull_request`, `push`, and other triggers that run without elevated permissions

The rule does NOT fire on privileged triggers (`pull_request_target`, `workflow_run`, `issue_comment`, etc.) — those are handled by the critical variant.

### Related Rules

- **[container-env-injection-critical]({{< ref "containerenvinjectioncritical.md" >}})**: Detects the same pattern in privileged workflows (higher severity)
- **[envvar-injection-medium]({{< ref "envvarinjectionmedium.md" >}})**: Detects `$GITHUB_ENV` injection in normal contexts
- **[code-injection-medium]({{< ref "codeinjectionmedium.md" >}})**: Detects direct code injection in normal contexts

### References

- [CVE-2022-39321 (GHSA-2c6m-6gqh-6qg3)](https://github.com/advisories/GHSA-2c6m-6gqh-6qg3) - Docker environment variable escaping vulnerability (patched, but env pollution risk remains)
- [Synacktiv: GitHub Actions Exploitation — Repo Jacking and Environment Manipulation](https://www.synacktiv.com/en/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation) - LD_PRELOAD and environment manipulation techniques
- [GitHub Security: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

### Testing

```bash
# Detect vulnerable patterns
sisakulint script/actions/containerenvinjection-medium.yaml

# With debug output
sisakulint -debug script/actions/containerenvinjection-medium.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore container-env-injection-medium
```
