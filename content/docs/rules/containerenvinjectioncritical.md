---
title: "Container Env Injection Rule (Critical)"
weight: 11
bookToc: true
---

### Container Env Injection Rule (Critical) Overview

This rule detects untrusted input in `container.env` or `services.*.container.env` fields within **privileged workflow triggers**. When an attacker controls these values, they can pollute the container's environment with dangerous variables such as `LD_PRELOAD`, `BASH_ENV`, or `PATH`, enabling code execution and secret exfiltration inside the container.

#### Key Features:

- **Privileged Context Detection**: Identifies dangerous patterns in `pull_request_target`, `workflow_run`, `issue_comment`, and other privileged triggers
- **Container Environment Analysis**: Checks both job-level `container.env` and service container `services.*.container.env`
- **Environment Variable Pollution Detection**: Detects untrusted input that can override security-critical variables inside containers
- **Zero False Positives**: Does not flag trusted inputs like `github.sha`

### Security Impact

**Severity: Critical (9/10)**

Container environment variable pollution in privileged workflows represents a critical vulnerability:

1. **`LD_PRELOAD` Hijacking**: Attackers can set `LD_PRELOAD` to a malicious shared library, hijacking all dynamically linked processes in the container
2. **`BASH_ENV` Code Execution**: Setting `BASH_ENV` to a malicious script causes Bash to source it before every command execution
3. **`PATH` Manipulation**: Overriding `PATH` makes legitimate commands resolve to attacker-controlled binaries
4. **Secret Exfiltration**: In privileged workflows, the container has access to secrets — polluted environment variables can redirect or capture them
5. **Service Container Compromise**: Service containers (databases, caches) can be manipulated through injected environment variables

This vulnerability is classified as **CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')** and aligns with OWASP CI/CD Security Risk **CICD-SEC-04: Poisoned Pipeline Execution (PPE)**.

### Historical Context: CVE-2022-39321

CVE-2022-39321 (GHSA-2c6m-6gqh-6qg3) was a vulnerability in the GitHub Actions runner where `container.env` values were passed unsanitized as Docker `-e` flags, allowing injection of additional environment variables. **This specific Docker CLI injection was patched in actions/runner v2.299.1 (September 2022)** and is no longer exploitable on current GitHub-hosted or properly updated self-hosted runners.

However, **the broader risk of environment variable pollution remains unpatched**: even with the Docker CLI fix, attacker-controlled values set through `container.env` are still passed as legitimate environment variables inside the container. The container runtime faithfully sets these values, and dangerous variable names like `LD_PRELOAD`, `BASH_ENV`, and `PATH` have side effects that the Docker CLI fix does not address.

### Why This Rule Still Matters

| Attack Vector | Patched by CVE-2022-39321 fix? | Still exploitable? |
|--------------|:---:|:---:|
| Docker `-e` flag injection (extra env vars) | Yes | No |
| `LD_PRELOAD` set via legitimate container.env | No | **Yes** |
| `BASH_ENV` set via legitimate container.env | No | **Yes** |
| `PATH` override via legitimate container.env | No | **Yes** |
| Application-specific env var pollution | No | **Yes** |

The key insight: **the fix prevented injecting _additional_ environment variables, but did not prevent an attacker from controlling the _value_ of a legitimately declared environment variable**. If the workflow author writes `BRANCH: ${{ github.event.pull_request.head.ref }}` in `container.env`, the attacker fully controls that value inside the container.

### Privileged Workflow Triggers

The following triggers are considered privileged because they run with write access or secrets:

- **`pull_request_target`**: Runs with write permissions and secrets, but triggered by untrusted PRs
- **`workflow_run`**: Executes with elevated privileges after another workflow completes
- **`issue_comment`**: Triggered by comments from any user, including external contributors
- **`issues`**: Triggered by issue events, potentially from untrusted sources
- **`discussion_comment`**: Triggered by discussion comments from any user
- **`pull_request_review`**: Triggered by PR reviews from any user

### Example Vulnerable Workflow

```yaml
name: Vulnerable - Container Env Injection (Critical)

on:
  pull_request_target:  # PRIVILEGED: Has write access and secrets

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:18
      env:
        # CRITICAL: attacker controls head.ref — value is set inside the container as-is
        BRANCH: ${{ github.event.pull_request.head.ref }}
    services:
      redis:
        image: redis
        env:
          # CRITICAL: issue body is attacker-controlled
          CUSTOM: ${{ github.event.issue.body }}
    steps:
      - run: echo "Building branch $BRANCH"
```

### Attack Scenario

**How Container Env Pollution Exploits Privileged Workflows:**

1. **Attacker Creates Malicious PR**: Opens a PR with a crafted branch name or body containing a payload targeting environment-sensitive behavior

2. **Workflow Triggers**: `pull_request_target` runs with write permissions and secrets

3. **Environment Pollution**: The attacker-controlled value is set as a legitimate environment variable inside the container. For example, if the workflow sets a variable whose value is used in shell commands, the attacker can inject shell metacharacters

4. **Downstream Impact**: Code running inside the container consumes the poisoned environment:
   - Build tools may read the variable and behave unexpectedly
   - Shell scripts may use the value without sanitization
   - `npm install`, `pip install`, and other package managers respect environment variables that can redirect downloads

5. **Secret Exfiltration**: In privileged workflows, the container has access to `GITHUB_TOKEN` and other secrets, which can be exfiltrated through manipulated build behavior

### Safe Pattern

Use only trusted, static values or validated inputs in container environment variables:

```yaml
name: Safe - Container Env Injection (Fixed)

on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:18
      env:
        # SAFE: using trusted values only
        NODE_ENV: production
        COMMIT_SHA: ${{ github.sha }}
    services:
      redis:
        image: redis
        env:
          # SAFE: static value
          REDIS_PORT: "6379"
    steps:
      - run: echo "Building commit $COMMIT_SHA"
```

### Detection Details

The rule detects:

1. **Untrusted input in `container.env`**: Job-level container environment variables with attacker-controlled expressions
2. **Untrusted input in `services.*.container.env`**: Service container environment variables with attacker-controlled expressions
3. **Untrusted input sources** including:
   - `github.event.pull_request.head.ref`
   - `github.event.pull_request.title`
   - `github.event.pull_request.body`
   - `github.event.issue.body`
   - `github.event.comment.body`
   - `github.event.workflow_run.head_branch`
   - And other user-controlled fields

### Related Rules

- **[container-env-injection-medium]({{< ref "containerenvinjectionmedium.md" >}})**: Detects the same pattern in normal (non-privileged) workflows
- **[envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}})**: Detects `$GITHUB_ENV` injection in privileged contexts
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: Detects direct code injection in privileged contexts

### References

- [CVE-2022-39321 (GHSA-2c6m-6gqh-6qg3)](https://github.com/advisories/GHSA-2c6m-6gqh-6qg3) - Docker environment variable escaping vulnerability in GitHub Actions runner (patched, but env pollution risk remains)
- [Synacktiv: GitHub Actions Exploitation — Repo Jacking and Environment Manipulation](https://www.synacktiv.com/en/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation) - LD_PRELOAD and environment manipulation techniques
- [GitHub Security: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

### Testing

```bash
# Detect vulnerable patterns
sisakulint script/actions/containerenvinjection-critical.yaml

# With debug output
sisakulint -debug script/actions/containerenvinjection-critical.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore container-env-injection-critical
```
