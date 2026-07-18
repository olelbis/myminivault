# Security Policy

myminivault is an experimental personal project and has not been independently
audited. Please do not treat it as a production password manager.

## Reporting A Vulnerability

Please report non-sensitive review feedback through GitHub issues. For
vulnerabilities with exploitable details, use GitHub private security advisories
instead of public issues:

```text
https://github.com/olelbis/myminivault/security/advisories/new
```

Useful reports include:

- cryptographic design issues
- encrypted file format parsing issues
- recovery workflow issues
- token workflow issues
- unsafe plaintext exposure
- release, packaging, or supply-chain issues

Valid security findings can be publicly credited in the README or release notes
unless the reporter prefers to remain anonymous.

## Current Trust Status

- Experimental and unaudited.
- Automated tests, CI, CodeQL, `govulncheck`, SBOMs, checksums, and GitHub
  artifact attestations are used as project hygiene, not as a substitute for an
  independent audit.
- The security model is documented in `docs/security.md`.
- The encrypted file format is documented in `docs/format.md`.
- The focused review scope is documented in `docs/crypto-review-scope.md`.
- The ready-to-share review request is documented in `docs/review-request.md`.

## Disclosure Expectations

Please give the maintainer reasonable time to understand and fix confirmed
issues before public disclosure. This project does not currently offer a paid
bug bounty.
