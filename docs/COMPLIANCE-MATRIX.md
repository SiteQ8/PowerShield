# PowerShield Compliance Matrix

This document maps every PowerShield check to its corresponding standards reference.

## Module 1: Account Policies

| Check | CIS | NIST 800-53 | DISA STIG | Description |
|-------|-----|-------------|-----------|-------------|
| Password history >= 24 | 1.1.1 | IA-5(1)(e) | V-205658 | Enforce password history |
| Max password age <= 365 | 1.1.2 | IA-5(1)(d) | V-205659 | Maximum password age |
| Min password age >= 1 | 1.1.3 | IA-5(1)(d) | V-205660 | Minimum password age |
| Min password length >= 14 | 1.1.4 | IA-5(1)(a) | V-205661 | Minimum password length |
| Password complexity enabled | 1.1.5 | IA-5(1)(a) | V-205662 | Complexity requirements |
| Reversible encryption disabled | 1.1.6 | IA-5(1)(c) | V-205663 | Store passwords securely |
| Lockout duration >= 15 | 1.2.1 | AC-7 | V-205710 | Account lockout duration |
| Lockout threshold 1-5 | 1.2.2 | AC-7 | V-205711 | Failed logon attempts |
| Reset lockout counter >= 15 | 1.2.3 | AC-7 | V-205712 | Lockout counter reset |

## Module 2: Local Policies

| Check | CIS | NIST 800-53 | DISA STIG | Description |
|-------|-----|-------------|-----------|-------------|
| Built-in Administrator disabled | 2.3.1.1 | AC-6(1) | V-205713 | Disable default admin |
| Guest account disabled | 2.3.1.2 | AC-6(1) | V-205714 | Disable guest account |
| Blank password console-only | 2.3.1.3 | IA-5(1) | V-205715 | Restrict blank passwords |
| Don't display last username | 2.3.7.1 | AC-9 | V-205717 | Logon information display |
| Inactivity timeout <= 900s | 2.3.7.4 | AC-11 | V-205718 | Machine inactivity limit |
| SMB client signing (always) | 2.3.8.1 | SC-8 | V-205719 | Network communications |
| SMB server signing (always) | 2.3.9.1 | SC-8 | V-205720 | Network communications |
| Anonymous SAM enumeration blocked | 2.3.10.1 | AC-3 | V-205721 | Network access control |
| NTLMv2 only (level 5) | 2.3.11.7 | IA-2 | V-205722 | LAN Manager auth level |
| UAC Admin Approval Mode | 2.3.17.1 | AC-6 | V-205723 | Privilege escalation control |
| UAC installer detection | 2.3.17.3 | CM-7 | V-205724 | Application installation |
| UAC EnableLUA | 2.3.17.6 | AC-6 | V-205725 | User Account Control |

## Module 4: Windows Firewall

| Check | CIS | NIST 800-53 | DISA STIG | Description |
|-------|-----|-------------|-----------|-------------|
| Domain profile enabled | 9.1.1 | SC-7 | V-205726 | Firewall state |
| Domain inbound: Block | 9.1.2 | SC-7 | V-205727 | Default inbound action |
| Private profile enabled | 9.2.1 | SC-7 | V-205728 | Firewall state |
| Private inbound: Block | 9.2.2 | SC-7 | V-205729 | Default inbound action |
| Public profile enabled | 9.3.1 | SC-7 | V-205730 | Firewall state |
| Public inbound: Block | 9.3.2 | SC-7 | V-205731 | Default inbound action |

## Module 6: Network Security

| Check | CIS | NIST 800-53 | DISA STIG | Description |
|-------|-----|-------------|-----------|-------------|
| SMBv1 disabled | 18.4.x | SC-8 | V-205910 | Legacy protocol elimination |
| SMB encryption enabled | — | SC-8 | V-205911 | Data-in-transit protection |
| LLMNR disabled | 18.4.x | SC-7 | V-205912 | Name resolution poisoning |
| RDP NLA required | 18.9.x | IA-2 | V-205914 | Network Level Authentication |

## Module 10: TLS and Cryptography

| Check | CIS | NIST 800-53 | DISA STIG | Description |
|-------|-----|-------------|-----------|-------------|
| SSL 2.0 disabled | — | SC-13 | V-205950 | Deprecated protocol |
| SSL 3.0 disabled | — | SC-13 | V-205951 | Deprecated protocol |
| TLS 1.0 disabled | — | SC-13 | V-205952 | Deprecated protocol |
| TLS 1.1 disabled | — | SC-13 | V-205953 | Deprecated protocol |
| TLS 1.2 enabled | — | SC-13 | V-205954 | Current standard |
| RC4 ciphers disabled | — | SC-13 | V-205960 | Weak cipher |
| DES ciphers disabled | — | SC-13 | V-205961 | Weak cipher |
| NULL ciphers disabled | — | SC-13 | V-205962 | No encryption |

---

*This matrix is maintained alongside PowerShield.ps1. For the most current mappings, refer to the inline control references in the source code.*
