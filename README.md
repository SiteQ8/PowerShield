<div align="center">

<img src="docs/screenshots/banner.svg" width="100%" alt="PowerShield"/>

<br>

[![Version](https://img.shields.io/badge/version-2.0-0078d4?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-0078d4?style=flat-square)](LICENSE)
[![Windows Server](https://img.shields.io/badge/Server-2019%20|%202022-0078d4?style=flat-square)]()
[![CIS](https://img.shields.io/badge/CIS-aligned-0078d4?style=flat-square)]()
[![NIST](https://img.shields.io/badge/NIST_800--53-aligned-0078d4?style=flat-square)]()
[![DISA STIG](https://img.shields.io/badge/DISA_STIG-aligned-0078d4?style=flat-square)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-0078d4?style=flat-square&logo=powershell&logoColor=white)]()

**Enterprise-grade security baseline enforcement for Windows Server.**

[Documentation](#deployment) · [Modules](#hardening-modules) · [Standards](#compliance-alignment) · [Reporting](#reporting) · [Contributing](#contributing)

</div>

---

## Overview

PowerShield is an open-source PowerShell hardening framework for Windows Server 2019 and 2022. It performs **120+ security checks** across **12 modules**, aligned to CIS Benchmark, NIST SP 800-53, DISA STIG, and Microsoft Security Baselines.

The tool operates in three modes: **audit** (read-only assessment), **fix** (automated remediation with pre-change backups), and **dry-run** (change preview). All findings are exported as HTML, CSV, and JSON reports with compliance scoring and executive summaries.

### Design Principles

- **Zero dependencies** — Pure PowerShell 5.1+. No external modules, agents, or frameworks.
- **Non-destructive by default** — Audit mode makes no system changes. Every remediation is backed up.
- **Standards-mapped** — Every check references a specific CIS, NIST, or STIG control identifier.
- **Enterprise reporting** — HTML for management, CSV for GRC platforms, JSON for automation pipelines.
- **Modular execution** — Run the full assessment or target individual modules.

---

## Deployment

### Prerequisites

- Windows Server 2019 or 2022
- PowerShell 5.1 or later
- Administrator privileges
- No external module dependencies

### Installation

```powershell
git clone https://github.com/SiteQ8/PowerShield.git
cd PowerShield
```

### Execution

```powershell
# Audit only — read-only assessment, no system modifications
.\PowerShield.ps1 -Audit

# Audit with automatic remediation
.\PowerShield.ps1 -Fix

# Preview all changes before applying
.\PowerShield.ps1 -DryRun

# Target specific modules
.\PowerShield.ps1 -Module Firewall,Services,TLSCrypto

# Apply CIS Level 2 profile
.\PowerShield.ps1 -Fix -Profile level2
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Audit` | Switch | Read-only assessment. No system changes. Default mode. |
| `-Fix` | Switch | Assess and apply remediation. Backs up configs before changes. |
| `-DryRun` | Switch | Preview all changes without applying them. |
| `-Profile` | String | Compliance profile: `level1`, `level2`, `stig`. Default: `level1`. |
| `-Module` | String[] | Run specific modules by name (comma-separated). |
| `-Report` | Switch | Generate HTML report (generated automatically by default). |
| `-Version` | Switch | Display version number. |
| `-Help` | Switch | Display usage information. |

---

## Hardening Modules

| Module | CIS Reference | NIST Family | Checks | Description |
|--------|---------------|-------------|--------|-------------|
| **Account Policies** | 1.1–1.2 | IA | 9 | Password policy (history, age, length, complexity, reversible encryption) and account lockout (threshold, duration, reset counter) |
| **Local Policies** | 2.2–2.3 | AC, IA | 12 | Administrator/Guest accounts, blank password restriction, SMB signing, SAM enumeration, NTLMv2 enforcement, UAC, inactivity timeout |
| **Advanced Audit Policy** | 17 | AU | 15 | 15 subcategories: credential validation, account management, process creation, logon/logoff, privilege use, policy change, system integrity |
| **Windows Firewall** | 9 | SC | 12 | Domain/Private/Public profiles — enabled state, default inbound action, outbound action, logging |
| **Defender and Exploit Guard** | 18.9.47 | SI | 10 | Real-time protection, behavior monitoring, PUA, IOAV, MAPS, signature freshness, ASLR, Credential Guard |
| **Network Security** | 18.4 | SC, AC | 8 | SMBv1 elimination, SMB encryption, WinRM, LLMNR, NetBIOS, IPv6, RDP with NLA |
| **Windows Services** | 5 | CM | 20 | 20 unnecessary services: IIS, FTP, SNMP, UPnP, SSDP, Xbox, WSL, mobile hotspot, media sharing |
| **Registry Hardening** | 18 | CM | 14 | LSA Protection, WDigest, SEHOP, PowerShell logging, AlwaysInstallElevated, Remote Credential Guard |
| **Event Log Configuration** | 18.9.26 | AU | 6 | Application/Security/System/Setup log sizing, Sysmon detection, PowerShell module logging |
| **TLS and Cryptography** | — | SC-13 | 12+ | SSL 2.0/3.0 and TLS 1.0/1.1 deprecation, TLS 1.2/1.3 enforcement, weak cipher elimination |
| **Windows Update** | 18.9.108 | SI | 3 | Automatic update policy, patch currency, pending reboot detection |
| **Additional Hardening** | — | CM | 7 | Login banners, AutoPlay, BitLocker, Print Spooler, admin shares, Spectre/Meltdown, local admin count |

---

## Compliance Alignment

| Standard | Coverage | Application |
|----------|----------|-------------|
| **CIS Benchmark for Windows Server 2019/2022** | Level 1 + Level 2 | Account policies, local policies, audit configuration, firewall, services, registry, event logs, update policy |
| **NIST SP 800-53 Revision 5** | AC, AU, CM, IA, SC, SI | Access control, audit and accountability, configuration management, identification and authentication, system protection, information integrity |
| **DISA STIG** | CAT I, II, III | LSA protection, WDigest, Credential Guard, SEHOP, TLS configuration, cipher suites, BitLocker, administrative shares |
| **Microsoft Security Baselines** | Server 2019 / 2022 | Microsoft-recommended registry settings, Group Policy configurations, Windows Defender policies |

---

## Reporting

PowerShield generates three report formats with every execution:

| Format | Location | Purpose |
|--------|----------|---------|
| **HTML** | `C:\PowerShield\Logs\` | Visual report with color-coded findings, compliance score, and executive summary. Suitable for management and audit review. |
| **CSV** | `C:\PowerShield\Logs\` | Structured tabular export for GRC platforms, SIEM integration, and spreadsheet-based tracking. |
| **JSON** | `C:\PowerShield\Logs\` | Machine-readable output with full system metadata, summary statistics, and per-check results for API integration and CI/CD pipelines. |

Configuration backups are stored in `C:\PowerShield\Backups\` with timestamps, enabling rollback of any remediated setting.

---

## Output Format

```
  [PASS] CIS 1.1.5 — Password complexity: Enabled
  [FAIL] CIS 18.4.x — SMBv1: Enabled (critical — disable immediately)
  [WARN] NIST — Sysmon: Not detected (recommended for advanced logging)

  EXECUTIVE SUMMARY
  ─────────────────────────────────────────────
  System:         DC01 (Windows Server 2022 Datacenter)
  Domain:         CORP.LOCAL
  Compliance:     74.8%
  Critical Gaps:  3

═══════════════════════════════════════════════════
  PowerShield Hardening Summary
═══════════════════════════════════════════════════
  PASS:  89     FAIL:  18     WARN:  12     TOTAL: 119
  Score: 74.8% — Needs improvement

  Log:    C:\PowerShield\Logs\PowerShield-20260309-143022.log
  Report: C:\PowerShield\Logs\PowerShield-Report-20260309-143022.html
  Backup: C:\PowerShield\Backups\20260309-143022
═══════════════════════════════════════════════════
```

---

## Architecture

```
PowerShield.ps1
├── Parameter validation and initialization
├── Banner display and environment detection
├── Module execution (sequential or targeted)
│   ├── Module 01: Account Policies        (secedit export)
│   ├── Module 02: Local Policies          (registry queries)
│   ├── Module 03: Advanced Audit Policy   (auditpol queries)
│   ├── Module 04: Windows Firewall        (Get-NetFirewallProfile)
│   ├── Module 05: Defender / Exploit Guard (Get-MpPreference)
│   ├── Module 06: Network Security        (Get-SmbServerConfiguration)
│   ├── Module 07: Windows Services        (Get-Service)
│   ├── Module 08: Registry Hardening      (Get-ItemProperty)
│   ├── Module 09: Event Log Configuration (Get-WinEvent)
│   ├── Module 10: TLS / Cryptography      (SCHANNEL registry)
│   ├── Module 11: Windows Update          (Get-HotFix)
│   └── Module 12: Additional Hardening    (mixed)
├── Report generation (HTML, CSV, JSON)
├── Executive summary with critical findings
└── Compliance scoring and summary output
```

---

## Disclaimer

PowerShield modifies Windows registry and system settings when executed with the `-Fix` parameter. Organizations should:

1. Perform initial assessments with `-Audit` mode in production environments
2. Validate remediation impact with `-DryRun` before applying changes
3. Test all remediations in a non-production environment
4. Verify backups in `C:\PowerShield\Backups\` before and after execution
5. Maintain documented change management procedures

This tool is provided as-is under the MIT License. The authors assume no responsibility for system disruption caused by hardening operations.

---

## Contributing

Contributions are accepted for:

- Additional CIS, NIST, or STIG control implementations
- Pester test framework integration
- Support for Windows Server 2025
- PowerShell Gallery packaging
- Module-level documentation

Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and submission guidelines.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>PowerShield — Enterprise Windows Server Hardening Framework</sub><br>
  <sub><a href="https://github.com/SiteQ8">@SiteQ8</a> — Ali AlEnezi</sub><br>
  <sub>CIS Benchmark &middot; NIST SP 800-53 &middot; DISA STIG &middot; Microsoft Security Baselines</sub>
</div>
