---
title: "Rules"
weight: 1
bookCollapseSection: true
---

# sisakulint Rules

sisakulint provides comprehensive security rules for GitHub Actions workflows. Rules are categorized by severity and the security risks they address.

## Severity Summary

sisakulint categorizes security rules by severity based on CVSS scores, attack impact, and exploitability.

| Severity | Count | CVSS Range | Description |
|----------|-------|------------|-------------|
| **Critical** | 14 | 9.0-10.0 | Immediate risk, can lead to RCE or full compromise |
| **High** | 19 | 7.0-8.9 | Significant risk, enables serious attacks |
| **Medium** | 14 | 4.0-6.9 | Moderate risk, requires specific conditions |
| **Low** | 6 | 0.1-3.9 | Best practices, minimal direct security impact |

## Security Rules Overview

### Code Injection / Poisoned Pipeline Execution (CICD-SEC-04)

| Rule | Severity | Description |
|------|----------|-------------|
| [code-injection-critical]({{< ref "codeinjectioncritical.md" >}}) | Critical | Detects untrusted input in privileged workflow triggers |
| [code-injection-medium]({{< ref "codeinjectionmedium.md" >}}) | Medium | Detects untrusted input in normal workflow triggers |
| [envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}}) | Critical | Detects untrusted input written to $GITHUB_ENV in privileged triggers |
| [envvar-injection-medium]({{< ref "envvarinjectionmedium.md" >}}) | Medium | Detects untrusted input written to $GITHUB_ENV in normal triggers |
| [envpath-injection-critical]({{< ref "envpathinjectioncritical.md" >}}) | Critical | Detects untrusted input written to $GITHUB_PATH in privileged triggers |
| [envpath-injection-medium]({{< ref "envpathinjectionmedium.md" >}}) | Medium | Detects untrusted input written to $GITHUB_PATH in normal triggers |
| [output-clobbering-critical]({{< ref "outputclobbering.md" >}}) | Critical | Detects untrusted input written to $GITHUB_OUTPUT in privileged triggers |
| [output-clobbering-medium]({{< ref "outputclobbering.md" >}}) | Medium | Detects untrusted input written to $GITHUB_OUTPUT in normal triggers |
| [argument-injection-critical]({{< ref "argumentinjection.md" >}}) | Critical | Detects command-line argument injection in privileged triggers |
| [argument-injection-medium]({{< ref "argumentinjection.md" >}}) | Medium | Detects command-line argument injection in normal triggers |
| [request-forgery-critical]({{< ref "requestforgery.md" >}}) | Critical | Detects SSRF vulnerabilities in privileged triggers |
| [request-forgery-medium]({{< ref "requestforgery.md" >}}) | Medium | Detects SSRF vulnerabilities in normal triggers |
| [untrusted-checkout]({{< ref "untrustedcheckout.md" >}}) | Critical | Detects checkout of untrusted PR code in privileged contexts |
| [untrusted-checkout-toctou-critical]({{< ref "untrustedcheckouttoctoucritical.md" >}}) | Critical | Detects TOCTOU vulnerabilities with labeled event type and mutable refs |
| [untrusted-checkout-toctou-high]({{< ref "untrustedcheckouttoctouhigh.md" >}}) | High | Detects TOCTOU vulnerabilities with deployment environment and mutable refs |
| [reusable-workflow-taint]({{< ref "reusableworkflowtaint.md" >}}) | Critical | Detects untrusted input passed to reusable workflows |
| [unsound-contains]({{< ref "unsoundcontains.md" >}}) | Medium | Detects bypassable contains() function usage |

### Insufficient Flow Control (CICD-SEC-01)

| Rule | Severity | Description |
|------|----------|-------------|
| [dangerous-triggers-critical]({{< ref "dangeroustriggersrulecritical.md" >}}) | Critical | Detects privileged triggers without any security mitigations |
| [dangerous-triggers-medium]({{< ref "dangeroustriggersrulemedium.md" >}}) | Medium | Detects privileged triggers with partial security mitigations |
| [improper-access-control]({{< ref "improperaccesscontrol.md" >}}) | High | Detects label-based approval bypass vulnerabilities |
| [bot-conditions]({{< ref "botconditions.md" >}}) | High | Detects spoofable bot detection conditions |

### Artifact and Cache Poisoning (CICD-SEC-09)

| Rule | Severity | Description |
|------|----------|-------------|
| [artifact-poisoning-critical]({{< ref "artifactpoisoningcritical.md" >}}) | Critical | Detects artifact poisoning in privileged workflows |
| [artifact-poisoning-medium]({{< ref "artifactpoisoningmedium.md" >}}) | Medium | Detects artifact poisoning in normal workflows |
| [cache-poisoning]({{< ref "cachepoisoningrule.md" >}}) | High | Detects cache poisoning vulnerabilities |
| [cache-poisoning-poisonable-step]({{< ref "cachepoisoningpoisonablesteprule.md" >}}) | High | Detects poisonable steps after unsafe checkout |
| [cache-bloat]({{< ref "cachebloatrule.md" >}}) | Low | Detects cache bloat issues with cache/restore and cache/save |
| [artipacked]({{< ref "artipacked.md" >}}) | Critical | Detects credential leakage via persisted checkout credentials |
| [secrets-in-artifacts]({{< ref "secretsinartifacts.md" >}}) | High | Detects secrets exposure in uploaded artifacts |

### Identity and Access Management (CICD-SEC-02)

| Rule | Severity | Description |
|------|----------|-------------|
| [permissions]({{< ref "permissions.md" >}}) | High | Validates GITHUB_TOKEN permission scopes |
| [secret-exposure]({{< ref "secretexposure.md" >}}) | High | Detects excessive secrets exposure patterns |
| [unmasked-secret-exposure]({{< ref "unmaskedsecretexposure.md" >}}) | High | Detects unmasked secret exposure from fromJson() |
| [secrets-inherit]({{< ref "secretsinherit.md" >}}) | High | Detects excessive secret inheritance in reusable workflow calls |
| [secret-exfiltration]({{< ref "secretexfiltration.md" >}}) | Critical | Detects secret exfiltration to external services |

### Credential Hygiene (CICD-SEC-06)

| Rule | Severity | Description |
|------|----------|-------------|
| [credentials]({{< ref "credentialrules.md" >}}) | High | Detects hardcoded credentials using Rego |

### Third Party Services (CICD-SEC-08)

| Rule | Severity | Description |
|------|----------|-------------|
| [action-list]({{< ref "actionlist.md" >}}) | Low | Enforces action allowlist/blocklist policies |
| [commit-sha]({{< ref "commitsharule.md" >}}) | High | Validates commit SHA pinning in actions |
| [known-vulnerable-actions]({{< ref "knownvulnerableactions.md" >}}) | Varies | Detects actions with known security vulnerabilities |
| [archived-uses]({{< ref "archiveduses.md" >}}) | Medium | Detects usage of archived actions |
| [impostor-commit]({{< ref "impostorcommit.md" >}}) | Critical | Detects impostor commits from fork network |
| [ref-confusion]({{< ref "refconfusion.md" >}}) | High | Detects ref confusion attacks |
| [unpinned-images]({{< ref "unpinnedimages.md" >}}) | Medium | Detects container images not pinned by SHA256 |

### Workflow Validation

| Rule | Severity | Description |
|------|----------|-------------|
| [id]({{< ref "idrule.md" >}}) | Low | Validates job and step IDs |
| [job-needs]({{< ref "jobneeds.md" >}}) | Low | Validates job dependencies |
| [workflow-call]({{< ref "workflowcall.md" >}}) | Medium | Validates reusable workflow calls |
| [timeout-minutes]({{< ref "timeoutminutesrule.md" >}}) | Low | Ensures timeout-minutes is set |

### Expression and Syntax Validation

| Rule | Severity | Description |
|------|----------|-------------|
| [expression]({{< ref "expressionrule.md" >}}) | Medium | Validates GitHub Actions expression syntax |
| [conditional]({{< ref "conditionalrule.md" >}}) | Medium | Validates conditional expressions |
| [environment-variable]({{< ref "environmentvariablerule.md" >}}) | Low | Validates environment variable names |
| [deprecated-commands]({{< ref "deprecatedcommandsrule.md" >}}) | High | Detects deprecated workflow commands |

### Runner Security

| Rule | Severity | Description |
|------|----------|-------------|
| [self-hosted-runners]({{< ref "selfhostedrunners.md" >}}) | High | Detects self-hosted runner usage in public repos |

### AI Agent Security

| Rule | Severity | Description |
|------|----------|-------------|
| [ai-action-unrestricted-trigger]({{< ref "aiactionunrestrictedtrigger.md" >}}) | High | Detects AI actions allowing any user to trigger execution via `allowed_non_write_users: "*"` |
| [ai-action-excessive-tools]({{< ref "aiactionexcessivetools.md" >}}) | High | Detects dangerous tool grants (Bash/Write/Edit) to AI agents in untrusted trigger contexts |
| [ai-action-prompt-injection]({{< ref "aiactionpromptinjection.md" >}}) | High | Detects untrusted input interpolated into AI agent prompt parameters (Clinejection) |

### Obfuscation Detection

| Rule | Severity | Description |
|------|----------|-------------|
| [obfuscation]({{< ref "obfuscation.md" >}}) | High | Detects obfuscated workflow patterns |

## Auto-Fix Support

The following rules support automatic fixing with `sisakulint -fix on`:

- **timeout-minutes** - Adds default timeout-minutes: 5
- **commit-sha** - Converts action tags to commit SHAs
- **credentials** - Removes hardcoded passwords
- **code-injection-critical/medium** - Moves untrusted expressions to environment variables
- **envvar-injection-critical/medium** - Sanitizes untrusted input before writing to $GITHUB_ENV
- **envpath-injection-critical/medium** - Validates paths with `realpath` before writing to $GITHUB_PATH
- **output-clobbering-critical/medium** - Transforms vulnerable patterns to heredoc syntax
- **argument-injection-critical/medium** - Adds end-of-options marker and environment variables
- **request-forgery-critical/medium** - Moves untrusted expressions to environment variables
- **untrusted-checkout** - Adds explicit ref to checkout in privileged contexts
- **untrusted-checkout-toctou-critical/high** - Fixes TOCTOU vulnerabilities
- **reusable-workflow-taint** - Converts unsafe patterns to use environment variables
- **artifact-poisoning-critical/medium** - Adds validation steps for artifact downloads
- **improper-access-control** - Replaces mutable refs with immutable SHAs and changes event types
- **conditional** - Removes unnecessary `${{ }}` wrappers
- **secret-exposure** - Converts bracket notation to dot notation
- **unmasked-secret-exposure** - Adds `::add-mask::` command for derived secrets
- **secrets-inherit** - Replaces `secrets: inherit` with explicit secret mappings
- **bot-conditions** - Replaces spoofable bot conditions with safe alternatives
- **artipacked** - Adds `persist-credentials: false` to checkout steps
- **secrets-in-artifacts** - Adds `include-hidden-files: false` for upload-artifact v3
- **unsound-contains** - Converts string literal to fromJSON() array format
- **impostor-commit** - Pins action to commit SHA
- **ref-confusion** - Pins action to commit SHA when ref confusion is detected
- **obfuscation** - Normalizes obfuscated paths and shell commands
- **known-vulnerable-actions** - Updates vulnerable actions to patched versions
- **cache-poisoning** - Removes unsafe ref from checkout step
- **cache-bloat** - Adds appropriate `if` conditions for cache/restore and cache/save
- **dangerous-triggers-critical/medium** - Adds `permissions: {}` to workflows

## OWASP CI/CD Top 10 Mapping

| OWASP Risk | Description | sisakulint Rules |
|------------|-------------|------------------|
| CICD-SEC-01 | Insufficient Flow Control Mechanisms | improper-access-control, bot-conditions, unsound-contains, dangerous-triggers-* |
| CICD-SEC-02 | Inadequate Identity and Access Management | permissions, secret-exposure, unmasked-secret-exposure, secrets-inherit, ai-action-unrestricted-trigger |
| CICD-SEC-03 | Dependency Chain Abuse | known-vulnerable-actions, archived-uses, impostor-commit, ref-confusion, reusable-workflow-taint |
| CICD-SEC-04 | Poisoned Pipeline Execution (PPE) | code-injection-*, envvar-injection-*, envpath-injection-*, output-clobbering-*, argument-injection-*, untrusted-checkout-* |
| CICD-SEC-05 | Insufficient PBAC (Pipeline-Based Access Controls) | self-hosted-runners |
| CICD-SEC-06 | Insufficient Credential Hygiene | credentials, artipacked, secrets-in-artifacts, secret-exfiltration, ai-action-excessive-tools, ai-action-prompt-injection |
| CICD-SEC-07 | Insecure System Configuration | timeout-minutes, deprecated-commands, cache-bloat |
| CICD-SEC-08 | Ungoverned Usage of 3rd Party Services | action-list, commit-sha, unpinned-images |
| CICD-SEC-09 | Improper Artifact Integrity Validation | artifact-poisoning-*, cache-poisoning-* |
| CICD-SEC-10 | Insufficient Logging and Visibility | obfuscation, request-forgery-* |
