# Changelog

## [2.0.0] - 2026-03-09

### Added
- 12 hardening modules (811 lines PowerShell)
- 120+ security checks (CIS, NIST, STIG, MS Baselines)
- Module 1: Account Policies (password, lockout)
- Module 2: Local Policies (UAC, SMB signing, NTLMv2)
- Module 3: Audit Policy (15 advanced subcategories)
- Module 4: Windows Firewall (3 profiles)
- Module 5: Defender & Exploit Guard (real-time, VBS, Credential Guard)
- Module 6: Network Security (SMBv1, LLMNR, NetBIOS, RDP/NLA)
- Module 7: Services (20 unnecessary services)
- Module 8: Registry Hardening (14 critical keys)
- Module 9: Event Logs (log sizes, Sysmon, PS logging)
- Module 10: TLS & Cryptography (SSL/TLS protocols, ciphers)
- Module 11: Windows Update (auto-update, patch age, reboot)
- Module 12: Additional (BitLocker, PrintNightmare, Spectre)
- HTML report generation with compliance score
- Auto-backup before every change
- CLI with -Audit, -Fix, -DryRun, -Module, -Profile
- GUI documentation page (docs/index.html)
- SVG banner, README with module table
