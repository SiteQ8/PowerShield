# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in PowerShield:

1. Do not open a public GitHub issue.
2. Send an email to **Site@hotmail.com** with the subject line: `[PowerShield Security] Brief description`.
3. Include steps to reproduce, affected module, and potential impact.

## Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgment | 48 hours |
| Status update | 7 business days |
| Resolution target | 30 calendar days |

## Scope

**In scope:** Script injection, privilege escalation through PowerShield, incorrect hardening that weakens security posture, credential exposure in logs or backups, report data leakage.

**Out of scope:** Vulnerabilities in Windows Server itself (report to Microsoft MSRC), CIS Benchmark content accuracy (report to CIS), third-party tool interactions.

## Important Note

PowerShield modifies Windows registry and system configuration when executed with the `-Fix` parameter. Always validate changes in a non-production environment before deploying to production systems.

The `-Audit` mode performs read-only assessment and is safe for production use.
