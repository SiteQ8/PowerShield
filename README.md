<div align="center">

<img src="docs/screenshots/banner.svg" width="100%" alt="PowerShield Banner"/>

<br>

[![Version](https://img.shields.io/badge/version-2.0-0078d4?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-0078d4?style=flat-square)](LICENSE)
[![Windows Server](https://img.shields.io/badge/Server-2019%20%7C%202022-0078d4?style=flat-square)]()
[![CIS](https://img.shields.io/badge/CIS_Benchmark-aligned-0078d4?style=flat-square)]()
[![NIST](https://img.shields.io/badge/NIST_800--53-aligned-0078d4?style=flat-square)]()
[![DISA STIG](https://img.shields.io/badge/DISA_STIG-aligned-0078d4?style=flat-square)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-0078d4?style=flat-square&logo=powershell&logoColor=white)]()
[![Checks](https://img.shields.io/badge/checks-120+-0078d4?style=flat-square)]()

**Your only destination for a secured Windows Server environment.**

[Quick Start](#-quick-start) · [Modules](#-modules) · [Usage](#-usage) · [Standards](#-standards) · [Contributing](#-contributing)

</div>

---

## What is PowerShield?

PowerShield is a **comprehensive PowerShell hardening tool** for Windows Server 2019/2022. It performs **120+ security checks** across 12 modules, aligned to CIS Benchmark, NIST 800-53, DISA STIG, and Microsoft Security Baselines.

```
One script. 12 modules. 120+ checks. Your Windows Server — secured.
```

### Why PowerShield?

- **Single script** — pure PowerShell 5.1+, no external dependencies
- **Audit + Fix** — find gaps AND remediate them automatically
- **Auto-backup** — registry and config backed up before every change
- **HTML reports** — professional reports for compliance evidence
- **Modular** — run all checks or target specific modules
- **4 standards** — CIS, NIST 800-53, DISA STIG, Microsoft Baselines
- **Server 2019 & 2022** — tested on Windows Server environments

---

## 🚀 Quick Start

```powershell
# Clone
git clone https://github.com/SiteQ8/PowerShield.git
cd PowerShield

# Audit only (safe — no changes)
.\PowerShield.ps1 -Audit

# Audit + auto-fix
.\PowerShield.ps1 -Fix

# Dry run (preview changes)
.\PowerShield.ps1 -DryRun

# Specific modules
.\PowerShield.ps1 -Module Firewall,Services,TLSCrypto

# CIS Level 2 profile
.\PowerShield.ps1 -Fix -Profile level2
```

### One-Liner (Download & Run)

```powershell
irm https://raw.githubusercontent.com/SiteQ8/PowerShield/main/PowerShield.ps1 -OutFile PowerShield.ps1; .\PowerShield.ps1 -Audit
```

---

## 📦 Modules

| # | Module | CIS Section | Checks | What It Does |
|---|--------|-------------|--------|--------------|
| 1 | **Account Policies** | CIS 1.1-1.2 | 9 | Password history/age/length/complexity, lockout duration/threshold/reset, reversible encryption |
| 2 | **Local Policies** | CIS 2.2-2.3 | 12 | Admin/Guest accounts, blank passwords, SMB signing, SAM enumeration, NTLMv2, UAC, inactivity timeout |
| 3 | **Audit Policy** | CIS 17 | 15 | Advanced audit: credential validation, account/group management, process creation, logon/logoff, privilege use, policy change |
| 4 | **Windows Firewall** | CIS 9 | 12 | Domain/Private/Public profiles — enabled, inbound block, outbound allow, logging |
| 5 | **Defender & Exploit Guard** | CIS 18.9.47 | 10 | Real-time protection, behavior monitoring, PUA, IOAV, cloud (MAPS), signature age, ASLR, Credential Guard |
| 6 | **Network Security** | CIS 18.4 | 8 | SMBv1 disable, SMB encryption, WinRM, LLMNR, NetBIOS, IPv6, RDP + NLA |
| 7 | **Services** | CIS 5 | 20 | 20 unnecessary services — Browser, IIS, FTP, SNMP, UPnP, Xbox, WSL, hotspot, media sharing |
| 8 | **Registry Hardening** | CIS 18 | 14 | AlwaysInstallElevated, WinRM basic/unencrypted, LSA Protection (RunAsPPL), WDigest, SEHOP, PS logging, Remote Credential Guard |
| 9 | **Event Logs** | CIS 18.9.26 | 6 | Application/Security/System/Setup log sizes, Sysmon detection, PowerShell module logging |
| 10 | **TLS & Cryptography** | NIST/STIG | 12+ | Disable SSL 2.0/3.0, TLS 1.0/1.1, enforce TLS 1.2/1.3, disable RC4/DES/NULL ciphers |
| 11 | **Windows Update** | CIS 18.9.108 | 3 | Auto-updates enabled, last patch age, pending reboot detection |
| 12 | **Additional Hardening** | NIST/STIG | 7 | Login banner, AutoPlay, BitLocker, Print Spooler (PrintNightmare), admin shares, Spectre/Meltdown, local admin count |

**Total: 120+ checks across 12 modules**

---

## 📋 Usage

```
.\PowerShield.ps1 [OPTIONS]

Options:
  -Audit          Audit only (no changes)
  -Fix            Audit + apply fixes
  -DryRun         Show what would change
  -Profile LEVEL  CIS profile: level1, level2, stig (default: level1)
  -Module MOD     Run specific module(s)
  -Report         Generate HTML report
  -Version        Show version
  -Help           Show this help

Available Modules:
  AccountPolicies, LocalPolicies, AuditPolicy, Firewall, Defender,
  NetworkSecurity, Services, RegistryHardening, EventLogs, TLSCrypto,
  WindowsUpdate, AdditionalHardening
```

### Output

```
  [PASS] CIS 1.1.5 — Password complexity: Enabled
  [FAIL] CIS 18.4.x — SMBv1: Enabled (critical — disable immediately)
  [WARN] NIST — Sysmon: Not detected (recommended)

═══════════════════════════════════════════════════
  PowerShield Hardening Summary
═══════════════════════════════════════════════════
  PASS:  89     FAIL:  18     WARN:  12
  Score: 73% — Needs improvement

  Log:    C:\PowerShield\Logs\PowerShield-20260309.log
  Report: C:\PowerShield\Logs\PowerShield-Report-20260309.html
  Backup: C:\PowerShield\Backups\20260309-143022
═══════════════════════════════════════════════════
```

---

## 📐 Standards Alignment

| Standard | Coverage | Description |
|----------|----------|-------------|
| **CIS Benchmark Server 2019/2022** | Level 1 + Level 2 | Industry gold standard for Windows hardening |
| **NIST SP 800-53 Rev 5** | AC, AU, CM, IA, SC, SI | Federal security and privacy controls |
| **DISA STIG** | CAT I, II, III | DoD technical implementation guidance |
| **Microsoft Security Baselines** | Server 2019/2022 | Microsoft-recommended security configurations |

---

## 🔒 What Gets Hardened

### Identity & Access
- Password policy (24 history, 365 max, 14 min length, complexity)
- Account lockout (5 attempts, 15 min duration)
- Guest/Administrator account management
- NTLMv2-only authentication
- UAC enforcement
- Blank password restriction

### Network
- SMBv1 disabled, SMB encryption enabled
- LLMNR and NetBIOS disabled (poisoning prevention)
- Windows Firewall — all profiles enabled, inbound blocked
- RDP with NLA enforcement
- IPv6 review

### Cryptography
- SSL 2.0/3.0 disabled, TLS 1.0/1.1 disabled
- TLS 1.2/1.3 enforced
- RC4, DES, NULL ciphers disabled
- SMB signing required

### Defender & Exploit Guard
- Real-time protection, behavior monitoring, PUA protection
- Cloud-delivered protection (MAPS)
- Credential Guard / VBS
- ASLR enforcement

### Audit & Logging
- 15 advanced audit subcategories
- PowerShell script block logging and transcription
- Event log sizing (Security: 196MB minimum)
- Sysmon detection

### Registry & Services
- LSA Protection (RunAsPPL)
- WDigest credential caching disabled
- AlwaysInstallElevated disabled
- 20 unnecessary services disabled
- Print Spooler (PrintNightmare) review
- Admin shares review

---

## 📊 Reports

HTML reports saved to `C:\PowerShield\Logs\`:
- Color-coded PASS/FAIL/WARN results
- System info (hostname, OS, profile)
- Compliance score percentage
- All backups in `C:\PowerShield\Backups\`

---

## ⚠️ Disclaimer

PowerShield modifies registry and system settings when run with `-Fix`. **Always**:

1. **Test in non-production first**
2. **Review audit report** before fixing
3. **Verify backups** in `C:\PowerShield\Backups\`
4. **Use `-DryRun`** to preview changes
5. **Keep a rollback plan**

---

## 🤝 Contributing

Contributions welcome — especially:
- 📋 More CIS/STIG checks
- 🧪 Pester test framework
- 📖 Module documentation
- 🐛 Bug fixes for different Windows versions
- 📦 PowerShell Gallery packaging

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  <sub>🛡️ PowerShield — Your only destination for a secured Windows Server environment</sub><br>
  <sub>Built by <a href="https://github.com/SiteQ8">@SiteQ8</a> — Ali AlEnezi 🇰🇼</sub><br>
  <sub>CIS Benchmark · NIST 800-53 · DISA STIG · Microsoft Baselines · 811 lines of PowerShell</sub>
</div>
