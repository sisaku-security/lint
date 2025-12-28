+++
title = 'Privacy Policy'
date = 2025-12-28
weight = 1
+++

# Privacy Policy

**Last Updated: December 28, 2025**

This Privacy Policy describes how sisakulint-agent ("we", "us", or "our") collects, uses, and shares information when you use our GitHub App.

## Information We Collect

### Repository Data
When you install sisakulint-agent on your GitHub repository, we access the following data:
- **Workflow files**: We read `.github/workflows/*.yml` and `.github/workflows/*.yaml` files to perform static analysis
- **Pull request metadata**: We access pull request information to post review comments
- **Issue comments**: We read and write issue comments to provide autofix functionality

### Users Data We Do NOT Collect
- We do **not** collect or store your source code beyond workflow files
- We do **not** collect personal information such as email addresses or names
- We do **not** store any repository data permanently
- We do **not** track user behavior or analytics

## How We Use Information

The data we access is used solely for:
1. **Static analysis**: Analyzing GitHub Actions workflow files for security issues
2. **Providing feedback**: Posting review comments on pull requests with detected issues
3. **Autofix functionality**: Suggesting and applying fixes for detected issues

## Data Retention

- We do **not** retain any repository data after analysis is complete
- All processing is done in real-time during webhook events
- No logs containing repository content are stored

## Data Sharing

We do **not** share, sell, or transfer any data to third parties.

## Security

We implement appropriate technical and organizational measures to protect your data:
- All communications use HTTPS encryption
- We follow GitHub's security best practices for GitHub Apps
- Our application runs in isolated environments

## Your Rights

You can:
- **Revoke access** at any time by uninstalling the GitHub App from your repository or organization
- **Request information** about the data we process by contacting us

## Changes to This Policy

We may update this Privacy Policy from time to time. We will notify you of any changes by updating the "Last Updated" date at the top of this policy.

## Contact Us

If you have any questions about this Privacy Policy, please:
- Open an issue at [https://github.com/sisaku-security/sisakulint-agent/issues](https://github.com/sisaku-security/sisakulint-agent/issues)
- Or contact the maintainers through the repository

## Open Source

sisakulint is open source software. You can review our code at:
- [https://github.com/ultra-supara/sisakulint](https://github.com/ultra-supara/sisakulint)
