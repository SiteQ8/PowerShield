# Changelog

## [2.0.0] - 2026-03-09

### Added
- 12 hardening modules (874 lines PowerShell)
- 120+ security checks aligned to CIS Benchmark, NIST 800-53, DISA STIG, and Microsoft Security Baselines
- HTML, CSV, and JSON report generation
- Executive summary with critical findings identification
- Compliance scoring with percentage-based assessment
- Auto-backup system for all configuration changes
- Module-level execution support (-Module parameter)
- CIS Level 1, Level 2, and STIG profile support
- Dry-run mode for change preview
- GUI documentation page (docs/index.html)
- Enterprise-grade landing page with module reference
- Professional SVG banner
- Community files (LICENSE, SECURITY, CONTRIBUTING, CHANGELOG)
- GitHub Actions CI with PSScriptAnalyzer
- Issue templates for bug reports and new check requests

### Modules
- Account Policies (CIS 1.1-1.2) — 9 checks
- Local Policies (CIS 2.2-2.3) — 12 checks
- Advanced Audit Policy (CIS 17) — 15 checks
- Windows Firewall (CIS 9) — 12 checks
- Defender and Exploit Guard (CIS 18.9.47) — 10 checks
- Network Security (CIS 18.4) — 8 checks
- Windows Services (CIS 5) — 20 checks
- Registry Hardening (CIS 18) — 14 checks
- Event Log Configuration (CIS 18.9.26) — 6 checks
- TLS and Cryptography (NIST/STIG) — 12+ checks
- Windows Update (CIS 18.9.108) — 3 checks
- Additional Hardening (NIST/STIG) — 7 checks
