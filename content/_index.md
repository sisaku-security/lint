+++
title = 'sisakulint Document'
date = 2024-10-06T02:14:29+09:00
draft = false
+++

# Find and auto-fix security vulnerabilities in GitHub Actions

**52 security rules. 38+ auto-fixes. Taint propagation. 100% detection on GitHub Security Lab advisories.**

{{< figure src="https://github.com/sisaku-security/homebrew-sisakulint/assets/67861004/e9801cbb-fbe1-4822-a5cd-d1daac33e90f" alt="sisakulint logo" width="300px" >}}

```bash
$ brew tap sisaku-security/homebrew-sisakulint
$ brew install sisakulint
```

{{< popup_link2 href="https://www.youtube.com/watch?v=DhgqKOmzLSk" >}}

{{< popup_link2 href=https://github.com/sisaku-security/sisakulint >}}

---

## What is sisakulint?

sisakulint is **a static and fast SAST (Static Application Security Testing) tool for GitHub Actions**. It automatically validates YAML workflow files according to security guidelines provided by GitHub.

### Why GitHub Actions Security Matters

GitHub Actions has become the de facto standard for CI/CD in open source projects. However, workflow files often contain security vulnerabilities that can lead to:

- **Supply chain attacks** - Malicious code injection through compromised dependencies
- **Credential leaks** - Exposed secrets in logs or artifacts
- **Privilege escalation** - Overly permissive GITHUB_TOKEN permissions
- **Code injection** - Untrusted input executed as code via `${{ }}` expressions

These vulnerabilities are frequently exploited in real-world attacks, making automated security scanning essential.

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Taint Propagation** | Tracks untrusted input across steps, jobs, and reusable workflows. No other GitHub Actions scanner does this. |
| **Auto-Fix (38+ rules)** | Don't just report — fix. Automatically remediate 38+ security issues. |
| **Supply Chain Detection** | Impostor commits, ref confusion, vulnerable actions. CVSS 9.8 coverage. |
| **OWASP CI/CD Top 10** | Full coverage of the OWASP CI/CD Top 10 Security Risks. |
| **SARIF Output** | Native SARIF format for reviewdog and GitHub Code Scanning integration. |
| **CI-Friendly** | Fast execution designed for CI/CD pipelines. |

---

## Validated Against Real-World Vulnerabilities

| Benchmark | Detection Rate |
|-----------|:--------------:|
| GitHub Security Lab (GHSL) advisories | **100% (18/18)** |
| GitHub Security Advisories (GHSA) | **81.6% (31/38)** |

Affected projects include: PX4-Autopilot, vets-api, weaviate, harvester, nrwl/nx, ag-grid

---

## Existing Tools and Their Limitations

GitHub Actions has become the de facto CI/CD platform, yet the security tooling landscape remains fragmented. Each tool addresses a different slice of the problem — no single tool previously combined deep semantic analysis with deterministic auto-fix and supply chain coverage.

| Capability | actionlint | zizmor | StepSecurity | Semgrep | GH Advanced Security | AI Security Agents* | **sisakulint** |
|------------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Security-focused rules | Limited | 24 | N/A (runtime) | Yes | Yes | AI-based (no static rules) | **Yes (52 rules)** |
| Taint propagation | No | No | No | Yes (Pro) | Yes | Partial | **Yes** |
| Supply chain detection | No | Limited | No | Limited | Limited | Limited | **Yes (CVSS 9.8)** |
| Multi-step analysis | No | No | No | Limited | Yes | Yes | **Yes** |
| Auto-fix (target code) | No | No | N/A | Limited | Yes (Copilot Autofix) | Yes | **Yes (38+ rules)** |

<small>*AI Security Agents: Claude Code Security (Anthropic, Feb 2026), Codex Security (OpenAI, Mar 2026). Both use AI-based detection — when a false positive occurs, there is no specific rule to trace or fix.</small>

**actionlint** focuses on syntax validation and best practices. **zizmor** is security-focused but limited to single-step pattern matching. **StepSecurity** takes a complementary runtime hardening approach via network restrictions and permissions. **AI Security Agents** represent a new class of tool that excels at finding novel vulnerabilities but cannot participate in a deterministic, self-healing loop.

### Two Levels of Automated Fixing

It is important to distinguish two levels of automated fixing in security tooling:

**Level 1: Target code autofix.** Systems like GitHub Copilot Autofix, SapFix, Getafix, and the newest AI agents (Claude Code Security, Codex Security) fix bugs in *application code* flagged by scanners. sisakulint itself has 38+ deterministic autofix rules at this level.

**Level 2: Scanner self-correction.** Our system operates at a fundamentally different level: it fixes the *scanner's own detection rule logic*, not target code. When sisakulint produces a false positive, the orchestration system reads the semantic context of the target repository and delegates root cause analysis to an agentic AI. This creates a **self-healing loop** — each fix permanently improves the scanner's detection capability.

---

## Security Rules (52 rules)

### Code Injection & Expression Safety

- **[code-injection-critical]({{< ref "docs/rules/codeinjectioncritical.md" >}})** - Detects code injection in privileged triggers
- **[code-injection-medium]({{< ref "docs/rules/codeinjectionmedium.md" >}})** - Detects code injection in normal triggers
- **[envvar-injection-critical]({{< ref "docs/rules/envvarinjectioncritical.md" >}})** - Environment variable injection in privileged triggers
- **[envvar-injection-medium]({{< ref "docs/rules/envvarinjectionmedium.md" >}})** - Environment variable injection in normal triggers
- **[envpath-injection-critical]({{< ref "docs/rules/envpathinjectioncritical.md" >}})** - PATH injection in privileged triggers
- **[envpath-injection-medium]({{< ref "docs/rules/envpathinjectionmedium.md" >}})** - PATH injection in normal triggers
- **[argument-injection rule]({{< ref "docs/rules/argumentinjection.md" >}})** - Detects command-line argument injection
- **[output-clobbering rule]({{< ref "docs/rules/outputclobbering.md" >}})** - Detects output clobbering vulnerabilities via $GITHUB_OUTPUT
- **[unsound-contains rule]({{< ref "docs/rules/unsoundcontains.md" >}})** - Detects unsafe contains() usage in conditions
- **[expression rule]({{< ref "docs/rules/expressionrule.md" >}})** - GitHub Actions expression syntax validation

### Supply Chain & Dependency Security

- **[commit-sha rule]({{< ref "docs/rules/commitSHARule.md" >}})** - Validates commit SHA usage in actions
- **[known-vulnerable-actions rule]({{< ref "docs/rules/knownvulnerableactions.md" >}})** - Detects actions with known vulnerabilities
- **[archived-uses rule]({{< ref "docs/rules/archiveduses.md" >}})** - Detects usage of archived/deprecated actions
- **[impostor-commit rule]({{< ref "docs/rules/impostorcommit.md" >}})** - Detects impostor commit attacks
- **[ref-confusion rule]({{< ref "docs/rules/refconfusion.md" >}})** - Detects ref confusion vulnerabilities
- **[unpinned-images rule]({{< ref "docs/rules/unpinnedimages.md" >}})** - Detects unpinned container images
- **[action-list rule]({{< ref "docs/rules/actionlist.md" >}})** - Action allowlist/blocklist enforcement

### Credential & Secret Protection

- **[credentials rule]({{< ref "docs/rules/credentialrules.md" >}})** - Hardcoded credentials detection using Rego
- **[secret-exposure rule]({{< ref "docs/rules/secretexposure.md" >}})** - Excessive secrets exposure detection
- **[unmasked-secret-exposure rule]({{< ref "docs/rules/unmaskedsecretexposure.md" >}})** - Detects unmasked secrets in logs
- **[secret-exfiltration rule]({{< ref "docs/rules/secretexfiltration.md" >}})** - Detects secret exfiltration via network commands
- **[secrets-in-artifacts rule]({{< ref "docs/rules/secretsinartifacts.md" >}})** - Detects sensitive data in artifact uploads
- **[secrets-inherit rule]({{< ref "docs/rules/secretsinherit.md" >}})** - Detects excessive secrets inheritance
- **[artipacked rule]({{< ref "docs/rules/artipacked.md" >}})** - Detects artipacked vulnerability patterns

### Pipeline Poisoning & Artifact Integrity

- **[untrusted-checkout rule]({{< ref "docs/rules/untrustedcheckout.md" >}})** - Detects checkout of untrusted PR code
- **[untrusted-checkout-to-ctou-critical]({{< ref "docs/rules/untrustedcheckouttoctoucritical.md" >}})** - Critical TOCTOU vulnerabilities in checkout
- **[untrusted-checkout-to-ctou-high]({{< ref "docs/rules/untrustedcheckouttoctouhigh.md" >}})** - High severity TOCTOU vulnerabilities in checkout
- **[artifact-poisoning-critical]({{< ref "docs/rules/artifactpoisoningcritical.md" >}})** - Artifact poisoning detection (critical)
- **[artifact-poisoning-medium]({{< ref "docs/rules/artifactpoisoningmedium.md" >}})** - Artifact poisoning detection (medium)
- **[cache-poisoning rule]({{< ref "docs/rules/cachepoisoningrule.md" >}})** - Cache poisoning vulnerability detection
- **[cache-poisoning-poisonable-step]({{< ref "docs/rules/cachepoisoningpoisonablesteprule.md" >}})** - Poisonable step detection after unsafe checkout
- **[reusable-workflow-taint rule]({{< ref "docs/rules/reusableworkflowtaint.md" >}})** - Detects untrusted inputs in reusable workflows

### Triggers & Access Control

- **[dangerous-triggers-critical rule]({{< ref "docs/rules/dangeroustriggersrulecritical.md" >}})** - Detects privileged triggers without mitigations
- **[dangerous-triggers-medium rule]({{< ref "docs/rules/dangeroustriggersrulemedium.md" >}})** - Detects privileged triggers with partial mitigations
- **[permissions rule]({{< ref "docs/rules/permissions.md" >}})** - Permission scope and value validation
- **[bot-conditions rule]({{< ref "docs/rules/botconditions.md" >}})** - Validates bot actor conditions in workflows
- **[improper-access-control rule]({{< ref "docs/rules/improperaccesscontrol.md" >}})** - Detects label-based approval bypass vulnerabilities
- **[self-hosted-runners rule]({{< ref "docs/rules/selfhostedrunners.md" >}})** - Self-hosted runner security validation
- **[request-forgery rule]({{< ref "docs/rules/requestforgery.md" >}})** - Detects SSRF vulnerabilities in workflows

### Workflow Quality & Best Practices

- **[id rule]({{< ref "docs/rules/idRule.md" >}})** - ID collision detection for jobs and environment variables
- **[timeout-minutes rule]({{< ref "docs/rules/timeoutminutesrule.md" >}})** - Ensures timeout-minutes is set
- **[workflow-call rule]({{< ref "docs/rules/workflowcall.md" >}})** - Reusable workflow call validation
- **[conditional rule]({{< ref "docs/rules/conditionalrule.md" >}})** - Validates conditional expressions
- **[deprecated-commands rule]({{< ref "docs/rules/deprecatedcommandsrule.md" >}})** - Detects deprecated workflow commands
- **[environment-variable rule]({{< ref "docs/rules/environmentvariablerule.md" >}})** - Environment variable name validation
- **[job-needs rule]({{< ref "docs/rules/jobneeds.md" >}})** - Job dependency validation
- **[obfuscation rule]({{< ref "docs/rules/obfuscation.md" >}})** - Detects obfuscated code in workflows

---

## Install

### macOS

```bash
$ brew tap sisaku-security/homebrew-sisakulint
$ brew install sisakulint
```

### Linux

Download from the [release page](https://github.com/sisaku-security/sisakulint/releases):

```bash
$ cd <directory where sisakulint binary is located>
$ mv ./sisakulint /usr/local/bin/sisakulint
```

## Usage

```bash
# Basic usage (scans .github/workflows/ in current directory)
$ sisakulint

# Remote scan — scan any GitHub repository without cloning
$ sisakulint -remote owner/repo

# Auto-fix (dry-run to preview changes)
$ sisakulint -fix dry-run

# Auto-fix (apply changes)
$ sisakulint -fix on

# SARIF output for reviewdog / GitHub Code Scanning
$ sisakulint -format "{{sarif .}}"

# With debug output
$ sisakulint -debug
```

---

## OWASP CI/CD Top 10 Mapping

| OWASP Risk | Description | sisakulint Rules |
|------------|-------------|------------------|
| CICD-SEC-01 | Insufficient Flow Control Mechanisms | timeout-minutes, dangerous-triggers-*, self-hosted-runners |
| CICD-SEC-02 | Inadequate Identity and Access Management | permissions, secret-exposure, unmasked-secret-exposure, bot-conditions |
| CICD-SEC-03 | Dependency Chain Abuse | known-vulnerable-actions, archived-uses, impostor-commit, ref-confusion, unpinned-images |
| CICD-SEC-04 | Poisoned Pipeline Execution (PPE) | code-injection-*, envvar-injection-*, envpath-injection-*, untrusted-checkout-*, unsound-contains, improper-access-control, deprecated-commands, obfuscation, reusable-workflow-taint, output-clobbering, argument-injection, request-forgery, impostor-commit, artifact-poisoning-*, cache-poisoning-* |
| CICD-SEC-05 | Insufficient PBAC (Pipeline-Based Access Controls) | self-hosted-runners |
| CICD-SEC-06 | Insufficient Credential Hygiene | credentials, artipacked, secret-exfiltration, secrets-in-artifacts, secrets-inherit |
| CICD-SEC-07 | Insecure System Configuration | self-hosted-runners, id, conditional, expression, job-needs, environment-variable, cache-bloat |
| CICD-SEC-08 | Ungoverned Usage of 3rd Party Services | action-list, commit-sha, workflow-call |
| CICD-SEC-09 | Improper Artifact Integrity Validation | artifact-poisoning-*, cache-poisoning-*, artipacked, secrets-in-artifacts |
| CICD-SEC-10 | Insufficient Logging and Visibility | - |

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/" >}}

---

## FAQ

**How is sisakulint different from actionlint?**
actionlint is an excellent syntax and best-practice linter for GitHub Actions. sisakulint builds on that foundation with 52 security-focused rules, taint propagation across steps and jobs, and 38+ auto-fixes. If actionlint is a spell checker, sisakulint is a security auditor.

**How is it different from zizmor?**
zizmor performs single-step pattern matching. sisakulint tracks data flow across multiple steps, jobs, and reusable workflows via taint propagation — catching vulnerabilities that single-step analysis fundamentally cannot detect (e.g., TOCTOU in checkout-to-use chains, cross-job secret exfiltration).

**Will it slow down my CI?**
No. sisakulint is designed for CI/CD pipelines and completes in seconds even on large monorepo workflow files. SARIF output integrates directly with reviewdog and GitHub Code Scanning.

**What about false positives?**
sisakulint achieves 100% detection on GitHub Security Lab advisories with a low false positive rate. Our Level 2 self-correction system continuously improves rule precision — when a false positive is confirmed, the scanner's own detection logic is automatically fixed and regression-tested.

**Can't AI agents (Claude Code Security, Codex Security) replace a static linter?**
AI agents excel at finding novel, context-dependent vulnerabilities. However, they operate non-deterministically — when a false positive occurs, there is no specific rule to trace, debug, or fix. sisakulint provides deterministic, reproducible results with traceable rules, while our self-healing architecture bridges the gap by using AI to improve the rules themselves.

---

## Architecture

![image](https://github.com/user-attachments/assets/4c6fa378-5878-48af-b95f-8b987b3cf7ef)

sisakulint automatically searches for YAML files in the `.github/workflows` directory. The parser builds an AST and traverses it to apply security and best practice rules. Results are output using a custom error formatter, with SARIF support for CI/CD integration.

---

## Achievements

- [Black Hat USA 2026](https://www.blackhat.com/) - The World's Premier Technical Security Conference in Las Vegas.
- [Black Hat Asia 2025](https://www.blackhat.com/asia-25/arsenal-overview.html) - The World's Premier Technical Security Conference in Singapore. ref: [Arsenal](https://www.blackhat.com/asia-25/arsenal/schedule/#sisakulint---ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions-43229)

---

## Links

- [GitHub Repository](https://github.com/sisaku-security/sisakulint)
- [Demo Video](https://www.youtube.com/watch?v=DhgqKOmzLSk)
- [Presentation (BlackHat Asia 2025)](https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions)
- [Poster](https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf)

{{< popup_link2 href=https://github.com/sisaku-security/sisakulint >}}
