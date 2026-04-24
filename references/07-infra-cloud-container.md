# Infrastructure, Cloud, and Container Security

## What to Check
Test server hardening, OS exposure, network security, firewall rules, DNS, email SPF/DKIM/DMARC, segmentation, reverse proxies, cloud IAM, storage, serverless, cloud networking, multi-cloud trust, Docker/Kubernetes/container isolation, and management plane exposure.

## How to Test (Active)
1. Run:
   `bash scripts/recon/port_scan.sh target.com --safe-mode`
   `bash scripts/recon/dns_recon.sh target.com --safe-mode`
   `bash scripts/infra/http_methods_test.sh https://target --safe-mode`
   `python3 scripts/infra/cloud_enum.py target.com --safe-mode`
   `bash scripts/infra/docker_escape_check.sh target.com --safe-mode`
2. Use `nmap -sV --top-ports 100 target` when authorized.
3. Check DNS records for dangling CNAMEs, SPF/DKIM/DMARC weakness, wildcard records, and split-horizon leaks.
4. Probe public cloud buckets only by exact discovered names and safe HEAD/list operations.
5. Test reverse proxy headers and HTTP method handling.

## What Good Looks Like (Pass Criteria)
Only required ports exposed, patched services, admin planes private, strong DNS/email auth, cloud assets tagged and owned, least-privilege IAM, public storage blocked, IMDSv2 or equivalent, Kubernetes API private, container workloads non-root with read-only filesystems, and network segmentation enforced.

## What Bad Looks Like (Fail Criteria)
Open databases, admin panels, Kubernetes dashboards, Docker socket exposure, public buckets, weak DMARC policy, dangling DNS, unrestricted security groups, default credentials, TRACE/PUT enabled unexpectedly, trusted proxy header spoofing, metadata access from workloads, and broad cloud roles.

## Exploitation Proof of Concept
For HTTP methods:
```bash
curl -isk -X TRACE https://target/
curl -isk -X PUT https://target/prodsec-test.txt --data test
```
`TRACE` echo or successful unauthorized `PUT` confirms a serious misconfiguration. Remove test objects immediately if created and authorized.

## Edge Cases & Hidden Traps
Look for IPv6 exposure, alternate ports, forgotten staging, CDN origin bypass, host header routing, default virtual hosts, cloud asset names leaked in JS, public snapshots, over-permissive cross-account roles, Kubernetes admission bypasses, and Docker layer secrets.

## Remediation
Close nonessential ports, restrict admin access by VPN/SSO, harden reverse proxy headers, enforce deny-by-default firewalls, fix DNS ownership, set SPF/DKIM/DMARC to reject, block public cloud storage by policy, least-privilege IAM, private cluster APIs, non-root containers, read-only filesystems, and runtime monitoring.

## References
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- Kubernetes Security: https://kubernetes.io/docs/concepts/security/
- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- CWE-284 Improper Access Control: https://cwe.mitre.org/data/definitions/284.html
