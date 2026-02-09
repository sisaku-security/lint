---
title: "Security Advisories"
weight: 3
bookCollapseSection: true
---

# GitHub Security Advisories Verification Results

This document summarizes sisakulint's detection capability against all 38 GitHub Security Advisories for the GitHub Actions ecosystem.

## Summary

| Metric | Value |
|--------|-------|
| Total Advisories | 38 |
| Detected (Direct) | 28 |
| Detected (Category Match) | 31 |
| Not Detectable | 7 |
| Detection Rate | 81.6% |

## Detection Categories

| Rule | Detections |
|------|-----------|
| code-injection-critical | 21 |
| known-vulnerable-actions | 16 |
| dangerous-triggers-critical | 11 |
| untrusted-checkout | 10 |
| code-injection-medium | 5 |
| argument-injection-critical | 2 |
| deprecated-commands | 2 |
| artifact-poisoning-critical | 1 |
| artifact-poisoning-medium | 1 |
| cache-poisoning-poisonable-step | 1 |
| argument-injection-medium | 1 |

## Detection Results

### Code Injection Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule |
|---------|--------|----------|----------|----------------|
| [GHSA-pwf7-47c3-mfhx]({{< ref "GHSA-pwf7-47c3-mfhx.md" >}}) | j178/prek-action | Critical | Yes | KnownVulnerableActionsRule, UntrustedCheckoutRule |
| [GHSA-65rg-554r-9j5x]({{< ref "GHSA-65rg-554r-9j5x.md" >}}) | lycheeverse/lychee-action | Moderate | Yes | KnownVulnerableActionsRule |
| [GHSA-2487-9f55-2vg9]({{< ref "GHSA-2487-9f55-2vg9.md" >}}) | OZI-Project/publish | Moderate | Yes | CodeInjectionMediumRule |
| [GHSA-7x29-qqmq-v6qc]({{< ref "GHSA-7x29-qqmq-v6qc.md" >}}) | ultralytics/actions | High | Yes | CodeInjectionCriticalRule, ArgumentInjectionCriticalRule |
| [GHSA-4xqx-pqpj-9fqw]({{< ref "GHSA-4xqx-pqpj-9fqw.md" >}}) | atlassian/gajira-create | Critical | Yes | CodeInjectionCriticalRule |
| [GHSA-rg3q-prf8-qxmp]({{< ref "GHSA-rg3q-prf8-qxmp.md" >}}) | embano1/wip | High | Yes | CodeInjectionMediumRule, ArgumentInjectionMediumRule |

### Command Injection Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule |
|---------|--------|----------|----------|----------------|
| [GHSA-gq52-6phf-x2r6]({{< ref "GHSA-gq52-6phf-x2r6.md" >}}) | tj-actions/branch-names | Critical | Yes | CodeInjectionCriticalRule |
| [GHSA-8v8w-v8xg-79rf]({{< ref "GHSA-8v8w-v8xg-79rf.md" >}}) | tj-actions/branch-names | Critical | Yes | CodeInjectionCriticalRule |
| [GHSA-ghm2-rq8q-wrhc]({{< ref "GHSA-ghm2-rq8q-wrhc.md" >}}) | tj-actions/verify-changed-files | High | Yes | UntrustedCheckoutRule |
| [GHSA-mcph-m25j-8j63]({{< ref "GHSA-mcph-m25j-8j63.md" >}}) | tj-actions/changed-files | High | Yes | DangerousTriggersRule |
| [GHSA-6q4m-7476-932w]({{< ref "GHSA-6q4m-7476-932w.md" >}}) | rlespinasse/github-slug-action | High | Yes | CodeInjectionCriticalRule |
| [GHSA-f9qj-7gh3-mhj4]({{< ref "GHSA-f9qj-7gh3-mhj4.md" >}}) | kartverket/github-workflows | High | Yes | CodeInjectionCriticalRule, UntrustedCheckoutRule |

### Secret/Token Exposure Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule |
|---------|--------|----------|----------|----------------|
| [GHSA-phf6-hm3h-x8qp]({{< ref "GHSA-phf6-hm3h-x8qp.md" >}}) | broadinstitute/cromwell | Critical | Yes | CodeInjectionCriticalRule |
| [GHSA-c5qx-p38x-qf5w]({{< ref "GHSA-c5qx-p38x-qf5w.md" >}}) | RageAgainstThePixel/setup-steamcmd | High | Yes | KnownVulnerableActionsRule |
| [GHSA-mj96-mh85-r574]({{< ref "GHSA-mj96-mh85-r574.md" >}}) | buildalon/setup-steamcmd | High | Yes | KnownVulnerableActionsRule |
| [GHSA-26wh-cc3r-w6pj]({{< ref "GHSA-26wh-cc3r-w6pj.md" >}}) | canonical/get-workflow-version-action | High | Yes | KnownVulnerableActionsRule |
| [GHSA-vqf5-2xx6-9wfm]({{< ref "GHSA-vqf5-2xx6-9wfm.md" >}}) | github/codeql-action | High | Yes | KnownVulnerableActionsRule |
| [GHSA-4mgv-m5cm-f9h7]({{< ref "GHSA-4mgv-m5cm-f9h7.md" >}}) | hashicorp/vault-action | High | Yes | KnownVulnerableActionsRule |
| [GHSA-g86g-chm8-7r2p]({{< ref "GHSA-g86g-chm8-7r2p.md" >}}) | check-spelling/check-spelling | Critical | Yes | KnownVulnerableActionsRule, DangerousTriggersRule |

### Argument/Expression Injection Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule |
|---------|--------|----------|----------|----------------|
| [GHSA-5xq9-5g24-4g6f]({{< ref "GHSA-5xq9-5g24-4g6f.md" >}}) | SonarSource/sonarqube-scan-action | High | Yes | DangerousTriggersRule, UntrustedCheckoutRule |
| [GHSA-f79p-9c5r-xg88]({{< ref "GHSA-f79p-9c5r-xg88.md" >}}) | SonarSource/sonarqube-scan-action | High | Yes | DangerousTriggersRule, UntrustedCheckoutRule |
| [GHSA-vxmw-7h4f-hqxh]({{< ref "GHSA-vxmw-7h4f-hqxh.md" >}}) | pypa/gh-action-pypi-publish | Low | Yes | DangerousTriggersRule, UntrustedCheckoutRule |
| [GHSA-xj87-mqvh-88w2]({{< ref "GHSA-xj87-mqvh-88w2.md" >}}) | fish-shop/syntax-check | Moderate | Yes | DangerousTriggersRule, UntrustedCheckoutRule |
| [GHSA-hw6r-g8gj-2987]({{< ref "GHSA-hw6r-g8gj-2987.md" >}}) | pytorch/pytorch | Moderate | Yes | CodeInjectionCriticalRule, ArgumentInjectionCriticalRule |
| [GHSA-7f32-hm4h-w77q]({{< ref "GHSA-7f32-hm4h-w77q.md" >}}) | rlespinasse/github-slug-action | Moderate | Yes | DeprecatedCommandsRule, CodeInjectionCriticalRule |

### Supply Chain / Artifact Poisoning Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule |
|---------|--------|----------|----------|----------------|
| [GHSA-qmg3-hpqr-gqvc]({{< ref "GHSA-qmg3-hpqr-gqvc.md" >}}) | reviewdog/action-setup | High | Partial | CommitShaRule (tag usage warning) |
| [GHSA-mrrh-fwg8-r2c3]({{< ref "GHSA-mrrh-fwg8-r2c3.md" >}}) | tj-actions/changed-files | High | Yes | KnownVulnerableActionsRule |
| [GHSA-5xr6-xhww-33m4]({{< ref "GHSA-5xr6-xhww-33m4.md" >}}) | dawidd6/action-download-artifact | High | Yes | ArtifactPoisoningMediumRule, KnownVulnerableActionsRule |
| [GHSA-cxww-7g56-2vh6]({{< ref "GHSA-cxww-7g56-2vh6.md" >}}) | actions/download-artifact | High | Yes | ArtifactPoisoningCriticalRule, KnownVulnerableActionsRule |
| [GHSA-h3qr-39j9-4r5v]({{< ref "GHSA-h3qr-39j9-4r5v.md" >}}) | gradle/gradle-build-action | High | Yes | CachePoisoningRule, UntrustedCheckoutRule |
| [GHSA-x6gv-2rvh-qmp6]({{< ref "GHSA-x6gv-2rvh-qmp6.md" >}}) | BoldestDungeon/steam-workshop-deploy | Critical | Yes | KnownVulnerableActionsRule |

### Miscellaneous Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule |
|---------|--------|----------|----------|----------------|
| [GHSA-mxr3-8whj-j74r]({{< ref "GHSA-mxr3-8whj-j74r.md" >}}) | step-security/harden-runner | Moderate | Partial | KnownVulnerableActionsRule |
| [GHSA-m32f-fjw2-37v3]({{< ref "GHSA-m32f-fjw2-37v3.md" >}}) | bullfrogsec/bullfrog | Moderate | No | Not detectable (runtime) |
| [GHSA-g85v-wf27-67xc]({{< ref "GHSA-g85v-wf27-67xc.md" >}}) | step-security/harden-runner | Low | Yes | KnownVulnerableActionsRule |
| [GHSA-p756-rfxh-x63h]({{< ref "GHSA-p756-rfxh-x63h.md" >}}) | Azure/setup-kubectl | Low | No | Not detectable (action internal) |
| [GHSA-2c6m-6gqh-6qg3]({{< ref "GHSA-2c6m-6gqh-6qg3.md" >}}) | actions/runner | High | Partial | DangerousTriggersRule |
| [GHSA-634p-93h9-92vh]({{< ref "GHSA-634p-93h9-92vh.md" >}}) | some-natalie/ghas-to-csv | Moderate | No | Not detectable (output format) |
| [GHSA-99jg-r3f4-rpxj]({{< ref "GHSA-99jg-r3f4-rpxj.md" >}}) | afichet/openexr-viewer | Critical | No | Not detectable (not workflow) |

## Non-Detection Categories

| Reason | Count | Examples |
|--------|-------|----------|
| Action internal implementation | 2 | GHSA-p756-rfxh-x63h (file permissions), GHSA-634p-93h9-92vh (CSV output) |
| Runtime behavior | 2 | GHSA-m32f-fjw2-37v3 (DNS filtering) |
| Not workflow related | 1 | GHSA-99jg-r3f4-rpxj (memory overflow in binary) |
| Time-bomb attacks (detected via KnownVulnerableActionsRule) | 2 | GHSA-qmg3-hpqr-gqvc, GHSA-mrrh-fwg8-r2c3 |

## Key Findings

1. **High Detection Rate**: sisakulint successfully detects 81.6% of all GitHub Actions advisories.

2. **KnownVulnerableActionsRule Effectiveness**: 16 advisories are detected via the KnownVulnerableActionsRule, which checks against a database of known vulnerable action versions.

3. **Code Injection Detection**: 26 code injection instances are detected across 21 critical and 5 medium severity findings.

4. **Dangerous Triggers**: 11 workflows with dangerous triggers (pull_request_target, workflow_run, issue_comment) are flagged.

5. **Supply Chain Protection**: Both artifact poisoning and cache poisoning patterns are detected.

## References

- [GitHub Security Advisories (Actions)](https://github.com/advisories?query=ecosystem%3Aactions)
- [sisakulint Documentation](https://sisaku-security.github.io/lint/)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
