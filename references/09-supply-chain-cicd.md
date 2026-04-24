# Supply Chain, Secure Coding, and CI/CD

## What to Check
Test secure coding controls, SAST triggers, DAST, SCA, threat modeling, memory safety, input sanitization, dependency safety, SBOM, build pipeline trust, artifact signing, secrets in pipelines, IaC security, branch protections, patching, and release provenance.

## How to Test (Active)
1. Run:
   `python3 scripts/crypto/secrets_scanner.py ./repo --safe-mode`
2. Run available ecosystem scanners: `npm audit`, `pip-audit`, `cargo audit`, `bundle audit`, `trivy fs .`, `semgrep`, `gitleaks`, `checkov`, or `tfsec`.
3. Inspect CI workflow permissions, untrusted pull request execution, secret exposure to forks, cache poisoning, dependency pinning, and artifact upload/download boundaries.
4. Attempt safe pipeline abuse in a test branch: modify dependency lockfile, inject benign command into allowed CI path, or alter artifact metadata.
5. Verify SBOM generation and artifact signature validation before deployment.

## What Good Looks Like (Pass Criteria)
Pinned dependencies, lockfiles enforced, least-privilege CI tokens, protected branches, required reviews, no secrets in fork PRs, signed artifacts, SBOMs, dependency update automation, IaC scanning, reproducible builds, and security tests blocking release.

## What Bad Looks Like (Fail Criteria)
Broad `GITHUB_TOKEN` permissions, secrets available to untrusted code, unsigned release artifacts, mutable tags, install scripts from unpinned URLs, stale critical CVEs, public CI logs with secrets, IaC opening public storage, and deployment from unreviewed branches.

## Exploitation Proof of Concept
Create a test-only CI change that prints a benign marker and attempts to read a fake secret variable:
```yaml
- run: echo "prodsec-ci-canary" && test -z "$FAKE_SECRET"
```
If real secrets are exposed to untrusted branches or pull requests, document names only, not values, and rotate immediately.

## Edge Cases & Hidden Traps
Check GitHub Actions `pull_request_target`, reusable workflows, poisoned caches, dependency confusion, typosquatting, postinstall scripts, Docker base images, Terraform state, package provenance, release asset replacement, and build logs retained outside normal access controls.

## Remediation
Set least-privilege CI permissions, separate build and deploy roles, block secrets in untrusted contexts, pin actions by SHA, enforce lockfiles, sign artifacts, produce SBOMs, scan IaC and dependencies, rotate leaked secrets, and require security gates for critical findings.

## References
- SLSA: https://slsa.dev/
- OWASP SCVS: https://owasp.org/www-project-software-component-verification-standard/
- GitHub Actions Security Hardening: https://docs.github.com/actions/security-guides/security-hardening-for-github-actions
- CWE-494 Download of Code Without Integrity Check: https://cwe.mitre.org/data/definitions/494.html
