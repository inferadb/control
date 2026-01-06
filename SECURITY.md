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

| Timeline | Action |
|----------|--------|
| 48 hours | Acknowledgment of your report |
| 7 days | Initial assessment and severity determination |
| 90 days | Target resolution for most issues |

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We'll work with you to understand the issue, develop a fix, and coordinate public disclosure.

## Scope

Security issues we're interested in include:

- Authentication/authorization bypasses
- Data exposure or leakage
- Injection vulnerabilities (SQL, command, etc.)
- Cryptographic weaknesses
- Denial of service (when practical to exploit)
- Supply chain vulnerabilities
- CI/CD security issues

## Out of Scope

- Vulnerabilities in dependencies (report to the upstream project)
- Social engineering attacks
- Physical security issues
- Issues requiring unlikely user interaction

## Security Updates

Security fixes are released as patch versions and announced via:
- GitHub Security Advisories
- Release notes

## Recognition

We appreciate security researchers who help keep InferaDB secure. With your permission, we'll acknowledge your contribution in the security advisory.
