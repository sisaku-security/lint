---
title: "Credentials Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Credentials Rule Overview

This rule detects hardcoded credentials in GitHub Actions workflows, specifically focusing on passwords within container and service definitions. Hardcoding sensitive information like passwords directly in workflow files is a critical security risk that can lead to credential exposure.

#### Key Features:

- **Container Password Detection**: Identifies hardcoded passwords in job container definitions
- **Service Password Detection**: Identifies hardcoded passwords in service container credentials
- **Expression Validation**: Recognizes GitHub Actions expressions (`${{ }}`) as safe patterns
- **Auto-fix Support**: Automatically removes hardcoded password fields
- **Zero False Negatives**: Does not flag secrets references or expression-based values

### Security Impact

**Severity: High (8/10)**

Hardcoded credentials in workflow files pose significant security risks:

1. **Version Control Exposure**: Credentials committed to version control are visible to anyone with repository access
2. **Fork Exposure**: Forked repositories inherit hardcoded credentials
3. **Log Exposure**: Hardcoded passwords may appear in CI/CD logs
4. **Rotation Difficulty**: Changing hardcoded credentials requires code changes and redeployment

This vulnerability is classified as **CWE-798: Use of Hard-coded Credentials** and **CWE-259: Use of Hard-coded Password**, and aligns with OWASP CI/CD Security Risk **CICD-SEC-6: Insufficient Credential Hygiene**.

### Attack Scenario

**How Hardcoded Credentials Lead to Supply Chain Compromise:**

1. **Developer hardcodes password** in workflow file
   - Password committed to repository history

2. **Repository is forked or accessed** by unauthorized user
   - Credentials are visible in workflow file (even in deleted commits)

3. **Attacker uses credentials** to access container registry
   - Pulls or pushes malicious container images

4. **Supply chain compromise**
   - Malicious images used in CI/CD pipeline affect downstream users

### Example Vulnerable Workflow

Consider this workflow with hardcoded container registry credentials:

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: user
        password: "hardcodedPassword123"  # Hardcoded credential detected
    services:
      redis:
        image: redis
        credentials:
          username: user
          password: "anotherHardcodedPassword456"  # Hardcoded credential detected
    steps:
      - run: echo 'hello'
```

### Example Output

Running sisakulint will detect hardcoded passwords in container and service definitions:

```bash
$ sisakulint

credentials.yaml:9:19: Password found in "Container" section, do not paste password direct hardcode [credentials]
      9 👈|        password: "hardcodedPassword123"

credentials.yaml:15:21: Password found in "Service" section for service redis, do not paste password direct hardcode [credentials]
      15 👈|          password: "anotherHardcodedPassword456"
```

### Detection Patterns

The rule checks the following locations for hardcoded passwords:

| Location | Description |
|----------|-------------|
| `jobs.<job_id>.container.credentials.password` | Job container credentials |
| `jobs.<job_id>.services.<service_id>.credentials.password` | Service container credentials |

**Safe (will NOT trigger an error):**
```yaml
credentials:
  username: user
  password: ${{ secrets.REGISTRY_PASSWORD }}  # Uses secrets - safe
```

**Hardcoded (will trigger an error):**
```yaml
credentials:
  username: user
  password: "myPassword123"  # Literal string - unsafe
  password: myPassword123    # Unquoted literal - unsafe
```

### Auto-fix Support

The credentials rule supports auto-fixing by removing the hardcoded password field:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

**Before (Vulnerable):**
```yaml
container:
  image: "example.com/image"
  credentials:
    username: user
    password: "hardcodedPassword123"
```

**After Auto-Fix:**
```yaml
container:
  image: "example.com/image"
  credentials:
    username: user
    # password field removed - you must add secrets reference manually
```

**Note:** Auto-fix removes the password field entirely. You must manually add a proper secrets reference (`${{ secrets.PASSWORD }}`) after the fix.

### Safe Patterns

#### Pattern 1: Using GitHub Secrets (Recommended)

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}  # Safe: Uses secrets
    steps:
      - run: echo 'hello'
```

#### Pattern 2: Using Environment Variables with Secrets

```yaml
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: "example.com/owner/image"
      credentials:
        username: ${{ vars.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}  # Safe
    steps:
      - run: echo 'hello'
```

### Best Practices

#### 1. Always Use GitHub Secrets

Store sensitive credentials in GitHub Secrets and reference them using expressions:

```yaml
credentials:
  password: ${{ secrets.MY_PASSWORD }}
```

#### 2. Use Organization-Level Secrets

For credentials used across multiple repositories, use organization-level secrets:

```yaml
credentials:
  password: ${{ secrets.ORG_REGISTRY_PASSWORD }}
```

#### 3. Rotate Credentials Regularly

Even when using secrets, implement regular credential rotation policies.

#### 4. Limit Secret Access

Use environment-scoped secrets for production credentials:

```yaml
jobs:
  deploy:
    environment: production
    steps:
      - name: Deploy
        env:
          DEPLOY_TOKEN: ${{ secrets.PRODUCTION_DEPLOY_TOKEN }}
```

### Complementary Rules

Use these rules together for defense in depth:

1. **[permissions]({{< ref "permissions.md" >}})**: Ensures workflows follow least-privilege principle
2. **[commit-sha]({{< ref "commitsharule.md" >}})**: Pins actions to prevent supply chain attacks
3. **[secret-exposure]({{< ref "secretexposure.md" >}})**: Detects excessive secrets exposure patterns

### See Also

**Industry References:**
- [GitHub Docs: Using Secrets in GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)
- [GitHub Docs: Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [OWASP Top 10 CI/CD Security Risks: CICD-SEC-6](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene)

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/encrypted-secrets" >}}

{{< popup_link2 href="https://cwe.mitre.org/data/definitions/798.html" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene" >}}
