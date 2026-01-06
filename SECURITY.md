# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Preferred: GitHub Private Vulnerability Reporting

The fastest way to report a vulnerability is through GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Fill out the form with details about the vulnerability

This creates a private discussion where we can collaborate on a fix before public disclosure.

### Alternative: Email

If you prefer email or cannot use GitHub's reporting:

- **Email:** [security@inferadb.com](mailto:security@inferadb.com)
- **Subject:** `[SECURITY] <brief description>`

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

| Timeline | Action                                        |
| -------- | --------------------------------------------- |
| 48 hours | Acknowledgment of your report                 |
| 7 days   | Initial assessment and severity determination |
| 90 days  | Target resolution for most issues             |

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We'll work with you to understand the issue, develop a fix, and coordinate public disclosure.

## Scope

Security issues we're interested in include:

- Test fixtures that could expose security vulnerabilities
- Insecure test patterns that might be copied
- Credential exposure in test configurations

## Out of Scope

- Vulnerabilities in test dependencies
- Issues that only affect test environments

## Security Updates

Security fixes are released as patch versions and announced via:

- GitHub Security Advisories
- Release notes

## Recognition

We appreciate security researchers who help keep InferaDB secure. With your permission, we'll acknowledge your contribution in the security advisory.
