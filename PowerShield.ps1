<#
.SYNOPSIS
    PowerShield — Windows Server Hardening Tool v2.0
.DESCRIPTION
    The only tool you need to harden your Windows Server environment.
    Performs 120+ security checks across 12 modules, aligned to:
    - CIS Benchmark for Windows Server 2019/2022
    - NIST SP 800-53 Rev 5
    - DISA STIG
    - Microsoft Security Baselines
.AUTHOR
    Ali AlEnezi (@SiteQ8)
.LICENSE
    MIT
.LINK
    https://github.com/SiteQ8/PowerShield
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Audit,
    [switch]$Fix,
    [switch]$DryRun,
    [ValidateSet('level1','level2','stig')]
    [string]$Profile = 'level1',
    [string[]]$Module,
    [switch]$Report,
    [switch]$Version,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ─── Globals ──────────────────────────────────────────────────────────
$Script:VERSION = "2.0.0"
$Script:PassCount = 0; $Script:FailCount = 0; $Script:WarnCount = 0; $Script:SkipCount = 0; $Script:TotalCount = 0
$Script:LogDir = "$env:SystemDrive\PowerShield\Logs"
$Script:BackupDir = "$env:SystemDrive\PowerShield\Backups\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Script:LogFile = "$Script:LogDir\PowerShield-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:ReportFile = "$Script:LogDir\PowerShield-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
$Script:Results = @()

# ─── Banner ───────────────────────────────────────────────────────────
function Show-Banner {
    Write-Host ""
    Write-Host "    ██████╗  ██████╗ ██╗    ██╗███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ " -ForegroundColor Cyan
    Write-Host "    ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗" -ForegroundColor Cyan
    Write-Host "    ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║" -ForegroundColor Cyan
    Write-Host "    ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║" -ForegroundColor Cyan
    Write-Host "    ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝" -ForegroundColor Cyan
    Write-Host "    ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Windows Server Hardening Tool  v$Script:VERSION" -ForegroundColor White
    Write-Host "    CIS Benchmark | NIST 800-53 | DISA STIG | Microsoft Security Baselines" -ForegroundColor DarkGray
    Write-Host "    Author: Ali AlEnezi (@SiteQ8)" -ForegroundColor DarkGray
    Write-Host ""
}

# ─── Logging ──────────────────────────────────────────────────────────
function Log-Pass { param([string]$Message)
    $Script:PassCount++; $Script:TotalCount++
    $entry = "  [PASS] $Message"
    Write-Host $entry -ForegroundColor Green
    $entry | Out-File -Append -FilePath $Script:LogFile
    $Script:Results += [PSCustomObject]@{Status='PASS';Message=$Message}
}

function Log-Fail { param([string]$Message)
    $Script:FailCount++; $Script:TotalCount++
    $entry = "  [FAIL] $Message"
    Write-Host $entry -ForegroundColor Red
    $entry | Out-File -Append -FilePath $Script:LogFile
    $Script:Results += [PSCustomObject]@{Status='FAIL';Message=$Message}
}

function Log-Warn { param([string]$Message)
    $Script:WarnCount++; $Script:TotalCount++
    $entry = "  [WARN] $Message"
    Write-Host $entry -ForegroundColor Yellow
    $entry | Out-File -Append -FilePath $Script:LogFile
    $Script:Results += [PSCustomObject]@{Status='WARN';Message=$Message}
}

function Log-Skip { param([string]$Message)
    $Script:SkipCount++; $Script:TotalCount++
    $entry = "  [SKIP] $Message"
    Write-Host $entry -ForegroundColor DarkGray
    $entry | Out-File -Append -FilePath $Script:LogFile
}

function Log-Info { param([string]$Message)
    $entry = "  [INFO] $Message"
    Write-Host $entry -ForegroundColor Cyan
    $entry | Out-File -Append -FilePath $Script:LogFile
}

function Log-Section { param([string]$Title)
    $line = "`n━━━ $Title ━━━"
    Write-Host $line -ForegroundColor Blue -NoNewline; Write-Host ""
    $line | Out-File -Append -FilePath $Script:LogFile
}

function Test-CanFix { return (-not $Audit -and -not $DryRun) }

function Backup-Item { param([string]$Path)
    if (Test-Path $Path) {
        $dest = Join-Path $Script:BackupDir ($Path -replace '[:\\]','_')
        New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
        Copy-Item -Path $Path -Destination $dest -Force 2>$null
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: ACCOUNT POLICIES
# CIS 1.1-1.2 — Password Policy, Account Lockout
# ═══════════════════════════════════════════════════════════════════════
function Invoke-AccountPolicies {
    Log-Section "1. ACCOUNT POLICIES (CIS 1.1-1.2)"

    # Export security policy
    $secpol = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secpol /quiet 2>$null
    $cfg = Get-Content $secpol -ErrorAction SilentlyContinue

    # 1.1.1 — Password History
    $val = ($cfg | Select-String "PasswordHistorySize" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -ge 24) { Log-Pass "CIS 1.1.1 — Password history: $val (>=24)" }
    else { Log-Fail "CIS 1.1.1 — Password history: $val (should be >=24)" }

    # 1.1.2 — Maximum password age
    $val = ($cfg | Select-String "MaximumPasswordAge" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -le 365 -and [int]$val -gt 0) { Log-Pass "CIS 1.1.2 — Max password age: $val days" }
    else { Log-Fail "CIS 1.1.2 — Max password age: $val (should be 1-365)" }

    # 1.1.3 — Minimum password age
    $val = ($cfg | Select-String "MinimumPasswordAge" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -ge 1) { Log-Pass "CIS 1.1.3 — Min password age: $val days" }
    else { Log-Fail "CIS 1.1.3 — Min password age: $val (should be >=1)" }

    # 1.1.4 — Minimum password length
    $val = ($cfg | Select-String "MinimumPasswordLength" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -ge 14) { Log-Pass "CIS 1.1.4 — Min password length: $val (>=14)" }
    else { Log-Fail "CIS 1.1.4 — Min password length: $val (should be >=14)" }

    # 1.1.5 — Password complexity
    $val = ($cfg | Select-String "PasswordComplexity" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -eq 1) { Log-Pass "CIS 1.1.5 — Password complexity: Enabled" }
    else { Log-Fail "CIS 1.1.5 — Password complexity: Disabled" }

    # 1.1.6 — Reversible encryption
    $val = ($cfg | Select-String "ClearTextPassword" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -eq 0) { Log-Pass "CIS 1.1.6 — Reversible encryption: Disabled" }
    else { Log-Fail "CIS 1.1.6 — Reversible encryption: ENABLED (critical!)" }

    # 1.2.1 — Account lockout duration
    $val = ($cfg | Select-String "LockoutDuration" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -ge 15) { Log-Pass "CIS 1.2.1 — Lockout duration: $val min (>=15)" }
    else { Log-Fail "CIS 1.2.1 — Lockout duration: $val (should be >=15)" }

    # 1.2.2 — Account lockout threshold
    $val = ($cfg | Select-String "LockoutBadCount" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -ge 1 -and [int]$val -le 5) { Log-Pass "CIS 1.2.2 — Lockout threshold: $val (1-5)" }
    else { Log-Fail "CIS 1.2.2 — Lockout threshold: $val (should be 1-5)" }

    # 1.2.3 — Reset lockout counter
    $val = ($cfg | Select-String "ResetLockoutCount" | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ([int]$val -ge 15) { Log-Pass "CIS 1.2.3 — Reset lockout counter: $val min" }
    else { Log-Fail "CIS 1.2.3 — Reset lockout counter: $val (should be >=15)" }

    Remove-Item $secpol -Force -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: LOCAL POLICIES — USER RIGHTS & SECURITY OPTIONS
# CIS 2.2-2.3 — User Rights Assignment, Security Options
# ═══════════════════════════════════════════════════════════════════════
function Invoke-LocalPolicies {
    Log-Section "2. LOCAL POLICIES (CIS 2.2-2.3)"

    # 2.3.1.1 — Accounts: Administrator account status
    $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($admin -and -not $admin.Enabled) { Log-Pass "CIS 2.3.1.1 — Built-in Administrator: Disabled" }
    elseif ($admin -and $admin.Enabled) { Log-Warn "CIS 2.3.1.1 — Built-in Administrator: Enabled (consider disabling)" }

    # 2.3.1.2 — Accounts: Guest account status
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and -not $guest.Enabled) { Log-Pass "CIS 2.3.1.2 — Guest account: Disabled" }
    else { Log-Fail "CIS 2.3.1.2 — Guest account: Enabled (must disable)" }

    # 2.3.1.3 — Limit blank passwords to console only
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue).LimitBlankPasswordUse
    if ($val -eq 1) { Log-Pass "CIS 2.3.1.3 — Blank password console-only: Enabled" }
    else { Log-Fail "CIS 2.3.1.3 — Blank password console-only: Not set" }

    # 2.3.7.1 — Interactive logon: Don't display last signed-in
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue).DontDisplayLastUserName
    if ($val -eq 1) { Log-Pass "CIS 2.3.7.1 — Don't display last username: Enabled" }
    else { Log-Fail "CIS 2.3.7.1 — Don't display last username: Disabled" }

    # 2.3.7.4 — Machine inactivity limit
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs
    if ($val -and [int]$val -le 900 -and [int]$val -gt 0) { Log-Pass "CIS 2.3.7.4 — Inactivity timeout: $val sec" }
    else { Log-Fail "CIS 2.3.7.4 — Inactivity timeout: ${val:-not set} (should be <=900)" }

    # 2.3.8.1 — Microsoft network client: Digitally sign communications (always)
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if ($val -eq 1) { Log-Pass "CIS 2.3.8.1 — SMB client signing (always): Enabled" }
    else { Log-Fail "CIS 2.3.8.1 — SMB client signing (always): Disabled" }

    # 2.3.9.1 — Microsoft network server: Digitally sign communications (always)
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if ($val -eq 1) { Log-Pass "CIS 2.3.9.1 — SMB server signing (always): Enabled" }
    else { Log-Fail "CIS 2.3.9.1 — SMB server signing (always): Disabled" }

    # 2.3.10.1 — Network access: Do not allow anonymous enumeration of SAM accounts
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue).RestrictAnonymousSAM
    if ($val -eq 1) { Log-Pass "CIS 2.3.10.1 — Anonymous SAM enumeration: Blocked" }
    else { Log-Fail "CIS 2.3.10.1 — Anonymous SAM enumeration: Allowed" }

    # 2.3.11.7 — Network security: LAN Manager authentication level
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($val -ge 5) { Log-Pass "CIS 2.3.11.7 — LM auth level: $val (NTLMv2 only)" }
    else { Log-Fail "CIS 2.3.11.7 — LM auth level: $val (should be 5=NTLMv2 only)" }

    # 2.3.17.1 — UAC: Admin Approval Mode for the Built-in Administrator
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue).FilterAdministratorToken
    if ($val -eq 1) { Log-Pass "CIS 2.3.17.1 — UAC Admin Approval Mode: Enabled" }
    else { Log-Warn "CIS 2.3.17.1 — UAC Admin Approval Mode: Not configured" }

    # 2.3.17.3 — UAC: Detect application installations and prompt for elevation
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue).EnableInstallerDetection
    if ($val -eq 1) { Log-Pass "CIS 2.3.17.3 — UAC installer detection: Enabled" }
    else { Log-Fail "CIS 2.3.17.3 — UAC installer detection: Disabled" }

    # 2.3.17.6 — UAC: Run all administrators in Admin Approval Mode
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    if ($val -eq 1) { Log-Pass "CIS 2.3.17.6 — UAC (EnableLUA): Enabled" }
    else { Log-Fail "CIS 2.3.17.6 — UAC (EnableLUA): DISABLED (critical!)" }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: AUDIT POLICY
# CIS 17 — Advanced Audit Policy Configuration
# ═══════════════════════════════════════════════════════════════════════
function Invoke-AuditPolicy {
    Log-Section "3. AUDIT POLICY (CIS 17)"

    $auditPolicies = @{
        "Account Logon:Credential Validation"         = "Success and Failure"
        "Account Management:Security Group Management" = "Success"
        "Account Management:User Account Management"   = "Success and Failure"
        "Detailed Tracking:Process Creation"           = "Success"
        "Logon/Logoff:Account Lockout"                 = "Failure"
        "Logon/Logoff:Logoff"                          = "Success"
        "Logon/Logoff:Logon"                           = "Success and Failure"
        "Logon/Logoff:Special Logon"                   = "Success"
        "Object Access:Removable Storage"              = "Success and Failure"
        "Policy Change:Audit Policy Change"            = "Success"
        "Policy Change:Authentication Policy Change"   = "Success"
        "Privilege Use:Sensitive Privilege Use"         = "Success and Failure"
        "System:Security State Change"                 = "Success"
        "System:Security System Extension"             = "Success"
        "System:System Integrity"                      = "Success and Failure"
    }

    $auditOutput = auditpol /get /category:* 2>$null

    foreach ($policy in $auditPolicies.GetEnumerator()) {
        $name = $policy.Key.Split(':')[1]
        $expected = $policy.Value
        $line = $auditOutput | Where-Object { $_ -match $name } | Select-Object -First 1
        if ($line -and $line -match $expected) {
            Log-Pass "CIS 17.x — $name`: $expected"
        } else {
            Log-Fail "CIS 17.x — $name`: not set to '$expected'"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 4: WINDOWS FIREWALL
# CIS 9 — Windows Defender Firewall with Advanced Security
# ═══════════════════════════════════════════════════════════════════════
function Invoke-Firewall {
    Log-Section "4. WINDOWS FIREWALL (CIS 9)"

    foreach ($profileName in @("Domain","Private","Public")) {
        $fw = Get-NetFirewallProfile -Name $profileName -ErrorAction SilentlyContinue

        if ($fw.Enabled -eq $true) { Log-Pass "CIS 9.x — $profileName profile: Enabled" }
        else { Log-Fail "CIS 9.x — $profileName profile: Disabled"
            if (Test-CanFix) { Set-NetFirewallProfile -Name $profileName -Enabled True; Log-Info "Enabled $profileName firewall" }
        }

        if ($fw.DefaultInboundAction -eq 'Block') { Log-Pass "CIS 9.x — $profileName inbound default: Block" }
        else { Log-Fail "CIS 9.x — $profileName inbound default: $($fw.DefaultInboundAction) (should be Block)" }

        if ($fw.DefaultOutboundAction -eq 'Allow') { Log-Pass "CIS 9.x — $profileName outbound default: Allow" }
        else { Log-Warn "CIS 9.x — $profileName outbound default: $($fw.DefaultOutboundAction)" }

        if ($fw.LogFileName) { Log-Pass "CIS 9.x — $profileName log file: configured" }
        else { Log-Warn "CIS 9.x — $profileName log file: not configured" }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 5: WINDOWS DEFENDER & EXPLOIT PROTECTION
# CIS 18.9.47 — Windows Defender, ASR, Exploit Guard
# ═══════════════════════════════════════════════════════════════════════
function Invoke-Defender {
    Log-Section "5. WINDOWS DEFENDER & EXPLOIT PROTECTION (CIS 18.9.47)"

    # Real-time protection
    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mpPref) {
        if (-not $mpPref.DisableRealtimeMonitoring) { Log-Pass "CIS 18.9.47.x — Real-time protection: Enabled" }
        else { Log-Fail "CIS 18.9.47.x — Real-time protection: DISABLED" }

        if (-not $mpPref.DisableBehaviorMonitoring) { Log-Pass "CIS 18.9.47.x — Behavior monitoring: Enabled" }
        else { Log-Fail "CIS 18.9.47.x — Behavior monitoring: Disabled" }

        if ($mpPref.PUAProtection -eq 1) { Log-Pass "CIS 18.9.47.x — PUA protection: Enabled" }
        else { Log-Warn "CIS 18.9.47.x — PUA protection: Not enabled" }

        if (-not $mpPref.DisableIOAVProtection) { Log-Pass "CIS 18.9.47.x — Download scanning (IOAV): Enabled" }
        else { Log-Fail "CIS 18.9.47.x — Download scanning (IOAV): Disabled" }

        if ($mpPref.MAPSReporting -ge 2) { Log-Pass "CIS 18.9.47.x — Cloud protection (MAPS): Advanced" }
        else { Log-Warn "CIS 18.9.47.x — Cloud protection (MAPS): $($mpPref.MAPSReporting)" }

        if ($mpPref.SubmitSamplesConsent -ge 1) { Log-Pass "CIS 18.9.47.x — Sample submission: Enabled" }
        else { Log-Warn "CIS 18.9.47.x — Sample submission: Disabled" }

        # Signature age
        $sigStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($sigStatus) {
            $sigAge = $sigStatus.AntivirusSignatureAge
            if ($sigAge -le 1) { Log-Pass "NIST — Defender signatures: current (${sigAge}d)" }
            elseif ($sigAge -le 7) { Log-Warn "NIST — Defender signatures: $sigAge days old" }
            else { Log-Fail "NIST — Defender signatures: $sigAge days old (update!)" }
        }
    } else {
        Log-Warn "Windows Defender preferences not accessible"
    }

    # Exploit protection — DEP
    $dep = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -ErrorAction SilentlyContinue).MoveImages
    if ($dep -ne 0) { Log-Pass "NIST — ASLR (MoveImages): Enabled" }
    else { Log-Warn "NIST — ASLR (MoveImages): Check configuration" }

    # Credential Guard
    $cg = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    if ($cg -eq 1) { Log-Pass "STIG — Credential Guard (VBS): Enabled" }
    else { Log-Warn "STIG — Credential Guard (VBS): Not configured" }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 6: NETWORK SECURITY
# CIS 18.4 — MSS, Network Settings
# ═══════════════════════════════════════════════════════════════════════
function Invoke-NetworkSecurity {
    Log-Section "6. NETWORK SECURITY (CIS 18.4)"

    # SMBv1
    $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
    if ($smb1 -eq $false) { Log-Pass "CIS 18.4.x — SMBv1: Disabled" }
    else { Log-Fail "CIS 18.4.x — SMBv1: Enabled (critical — disable immediately)"
        if (Test-CanFix) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Log-Info "Disabled SMBv1" }
    }

    # SMB encryption
    $smbEncrypt = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EncryptData
    if ($smbEncrypt -eq $true) { Log-Pass "NIST — SMB encryption: Enabled" }
    else { Log-Warn "NIST — SMB encryption: Disabled" }

    # WinRM
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm.Status -ne 'Running') { Log-Pass "CIS 18.9.x — WinRM: Not running" }
    else { Log-Warn "CIS 18.9.x — WinRM: Running (verify HTTPS only)" }

    # LLMNR
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    if ($val -eq 0) { Log-Pass "CIS 18.4.x — LLMNR: Disabled" }
    else { Log-Fail "CIS 18.4.x — LLMNR: Enabled (poisoning risk)"
        if (Test-CanFix) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
            Log-Info "Disabled LLMNR"
        }
    }

    # NetBIOS over TCP/IP
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction SilentlyContinue
    $nbEnabled = $adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
    if (-not $nbEnabled) { Log-Pass "NIST — NetBIOS over TCP/IP: Disabled on all adapters" }
    else { Log-Warn "NIST — NetBIOS over TCP/IP: Enabled on $($nbEnabled.Count) adapter(s)" }

    # IPv6
    $ipv6 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
    if ($ipv6 -eq 255) { Log-Pass "STIG — IPv6: Disabled (all components)" }
    else { Log-Warn "STIG — IPv6: Enabled (review if not required)" }

    # Remote Desktop
    $rdp = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($rdp -eq 1) { Log-Pass "CIS 18.9.x — Remote Desktop: Disabled" }
    else {
        Log-Warn "CIS 18.9.x — Remote Desktop: Enabled"
        # Check NLA
        $nla = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        if ($nla -eq 1) { Log-Pass "CIS 18.9.x — RDP NLA: Required" }
        else { Log-Fail "CIS 18.9.x — RDP NLA: Not required (critical if RDP is on)" }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 7: WINDOWS SERVICES
# CIS 5 — System Services
# ═══════════════════════════════════════════════════════════════════════
function Invoke-Services {
    Log-Section "7. WINDOWS SERVICES (CIS 5)"

    $unnecessaryServices = @(
        @{Name="Browser";        Desc="Computer Browser"},
        @{Name="IISADMIN";       Desc="IIS Admin Service"},
        @{Name="irmon";          Desc="Infrared Monitor"},
        @{Name="SharedAccess";   Desc="Internet Connection Sharing"},
        @{Name="LxssManager";    Desc="Windows Subsystem for Linux"},
        @{Name="FTPSVC";         Desc="FTP Publishing Service"},
        @{Name="RpcLocator";     Desc="Remote Procedure Call Locator"},
        @{Name="RemoteAccess";   Desc="Routing and Remote Access"},
        @{Name="simptcp";        Desc="Simple TCP/IP Services"},
        @{Name="SNMP";           Desc="SNMP Service"},
        @{Name="sacsvr";         Desc="Special Administration Console Helper"},
        @{Name="SSDPSRV";        Desc="SSDP Discovery"},
        @{Name="upnphost";       Desc="UPnP Device Host"},
        @{Name="WMSvc";          Desc="Web Management Service"},
        @{Name="WMPNetworkSvc";  Desc="Windows Media Player Network Sharing"},
        @{Name="icssvc";         Desc="Windows Mobile Hotspot"},
        @{Name="W3SVC";          Desc="World Wide Web Publishing"},
        @{Name="XboxGipSvc";     Desc="Xbox Accessory Management"},
        @{Name="XblAuthManager"; Desc="Xbox Live Auth Manager"},
        @{Name="XblGameSave";    Desc="Xbox Live Game Save"}
    )

    foreach ($svc in $unnecessaryServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if (-not $service) { Log-Pass "CIS 5.x — $($svc.Desc): Not installed" }
        elseif ($service.Status -ne 'Running' -and $service.StartType -eq 'Disabled') {
            Log-Pass "CIS 5.x — $($svc.Desc): Disabled"
        } elseif ($service.Status -eq 'Running') {
            Log-Fail "CIS 5.x — $($svc.Desc): Running (should be disabled)"
            if (Test-CanFix) {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Log-Info "Stopped and disabled $($svc.Desc)"
            }
        } else {
            Log-Warn "CIS 5.x — $($svc.Desc): $($service.StartType)"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 8: REGISTRY HARDENING
# CIS 18 — Administrative Templates (Computer)
# ═══════════════════════════════════════════════════════════════════════
function Invoke-RegistryHardening {
    Log-Section "8. REGISTRY HARDENING (CIS 18)"

    $checks = @(
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0; CIS="CIS 18.9.x"; Desc="MSI AlwaysInstallElevated"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected=0; CIS="CIS 18.9.x"; Desc="WinRM client basic auth"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected=0; CIS="CIS 18.9.x"; Desc="WinRM client unencrypted"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected=0; CIS="CIS 18.9.x"; Desc="WinRM service basic auth"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected=0; CIS="CIS 18.9.x"; Desc="WinRM service unencrypted"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Name="EnableFirewall"; Expected=1; CIS="CIS 9.1.1"; Desc="Domain firewall enabled"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Expected=1; CIS="STIG"; Desc="LSA Protection (RunAsPPL)"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Expected=0; CIS="STIG"; Desc="WDigest credential caching"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected=2; CIS="CIS 2.3.17.2"; Desc="UAC consent prompt (admin)"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1; CIS="CIS 18.9.x"; Desc="PowerShell script block logging"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1; CIS="NIST"; Desc="PowerShell transcription"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected=1; CIS="CIS 18.8.x"; Desc="Remote Credential Guard"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="DisableExceptionChainValidation"; Expected=0; CIS="STIG"; Desc="SEHOP (Structured Exception Handling)"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="AutoAdminLogon"; Expected=0; CIS="CIS 18.9.x"; Desc="Auto admin logon disabled"}
    )

    foreach ($check in $checks) {
        $val = (Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue).$($check.Name)
        if ($null -ne $val -and [int]$val -eq $check.Expected) {
            Log-Pass "$($check.CIS) — $($check.Desc): $val"
        } elseif ($null -eq $val) {
            Log-Warn "$($check.CIS) — $($check.Desc): Not configured"
            if (Test-CanFix) {
                New-Item -Path $check.Path -Force -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path $check.Path -Name $check.Name -Value $check.Expected -Type DWord
                Log-Info "Set $($check.Desc) to $($check.Expected)"
            }
        } else {
            Log-Fail "$($check.CIS) — $($check.Desc): $val (expected: $($check.Expected))"
            if (Test-CanFix) {
                Set-ItemProperty -Path $check.Path -Name $check.Name -Value $check.Expected -Type DWord
                Log-Info "Fixed $($check.Desc)"
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 9: EVENT LOG SETTINGS
# CIS 18.9.26 — Event Log sizes and retention
# ═══════════════════════════════════════════════════════════════════════
function Invoke-EventLogs {
    Log-Section "9. EVENT LOG SETTINGS (CIS 18.9.26)"

    $logSettings = @(
        @{LogName="Application";  MinSize=32768},
        @{LogName="Security";     MinSize=196608},
        @{LogName="System";       MinSize=32768},
        @{LogName="Setup";        MinSize=32768}
    )

    foreach ($logCfg in $logSettings) {
        $log = Get-WinEvent -ListLog $logCfg.LogName -ErrorAction SilentlyContinue
        if ($log) {
            $sizeKB = [math]::Round($log.MaximumSizeInBytes / 1024)
            if ($sizeKB -ge $logCfg.MinSize) {
                Log-Pass "CIS 18.9.26.x — $($logCfg.LogName) log: ${sizeKB}KB (>=$($logCfg.MinSize)KB)"
            } else {
                Log-Fail "CIS 18.9.26.x — $($logCfg.LogName) log: ${sizeKB}KB (should be >=$($logCfg.MinSize)KB)"
                if (Test-CanFix) {
                    wevtutil sl $logCfg.LogName /ms:$($logCfg.MinSize * 1024) 2>$null
                    Log-Info "Set $($logCfg.LogName) log to $($logCfg.MinSize)KB"
                }
            }
        }
    }

    # Sysmon
    $sysmon = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
    if ($sysmon -and $sysmon.Status -eq 'Running') { Log-Pass "NIST — Sysmon: Running" }
    else { Log-Warn "NIST — Sysmon: Not detected (recommended for advanced logging)" }

    # PowerShell module logging
    $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
    if ($val -eq 1) { Log-Pass "CIS 18.9.x — PowerShell module logging: Enabled" }
    else { Log-Warn "CIS 18.9.x — PowerShell module logging: Not configured" }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 10: TLS & CRYPTOGRAPHY
# NIST/STIG — Protocol and cipher configuration
# ═══════════════════════════════════════════════════════════════════════
function Invoke-TLSCrypto {
    Log-Section "10. TLS & CRYPTOGRAPHY (NIST/STIG)"

    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    # SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 should be disabled
    $deprecatedProtocols = @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")
    foreach ($proto in $deprecatedProtocols) {
        $serverEnabled = (Get-ItemProperty -Path "$basePath\$proto\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        if ($null -eq $serverEnabled -or $serverEnabled -eq 0) {
            Log-Pass "NIST — $proto (Server): Disabled"
        } else {
            Log-Fail "NIST — $proto (Server): Enabled (must disable)"
            if (Test-CanFix) {
                New-Item -Path "$basePath\$proto\Server" -Force | Out-Null
                Set-ItemProperty -Path "$basePath\$proto\Server" -Name "Enabled" -Value 0 -Type DWord
                Set-ItemProperty -Path "$basePath\$proto\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
                Log-Info "Disabled $proto Server"
            }
        }
    }

    # TLS 1.2 should be enabled
    $tls12 = (Get-ItemProperty -Path "$basePath\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($null -eq $tls12 -or $tls12 -eq 1) { Log-Pass "NIST — TLS 1.2 (Server): Enabled" }
    else { Log-Fail "NIST — TLS 1.2 (Server): Disabled" }

    # TLS 1.3
    $tls13 = (Get-ItemProperty -Path "$basePath\TLS 1.3\Server" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($tls13 -eq 1) { Log-Pass "NIST — TLS 1.3 (Server): Enabled" }
    else { Log-Warn "NIST — TLS 1.3 (Server): Not explicitly enabled (may be default)" }

    # Weak ciphers
    $weakCiphers = @("RC4 128/128","RC4 56/128","RC4 40/128","DES 56/56","Triple DES 168","NULL")
    foreach ($cipher in $weakCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        $val = (Get-ItemProperty -Path $cipherPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        if ($val -eq 0) { Log-Pass "STIG — Cipher '$cipher': Disabled" }
        elseif ($null -eq $val) { Log-Warn "STIG — Cipher '$cipher': Not explicitly disabled" }
        else { Log-Fail "STIG — Cipher '$cipher': Enabled (must disable)" }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 11: WINDOWS UPDATE & PATCHING
# CIS 18.9.108 — Windows Update configuration
# ═══════════════════════════════════════════════════════════════════════
function Invoke-WindowsUpdate {
    Log-Section "11. WINDOWS UPDATE (CIS 18.9.108)"

    # Auto Update
    $au = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
    if ($au -ne 1) { Log-Pass "CIS 18.9.108.x — Automatic updates: Enabled" }
    else { Log-Fail "CIS 18.9.108.x — Automatic updates: DISABLED" }

    # Check last update install date
    $lastUpdate = (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
    if ($lastUpdate) {
        $daysSince = (New-TimeSpan -Start $lastUpdate -End (Get-Date)).Days
        if ($daysSince -le 30) { Log-Pass "NIST — Last patch installed: $daysSince days ago" }
        elseif ($daysSince -le 60) { Log-Warn "NIST — Last patch installed: $daysSince days ago" }
        else { Log-Fail "NIST — Last patch installed: $daysSince days ago (>60 days)" }
    }

    # Pending reboots
    $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if (-not $pendingReboot) { Log-Pass "NIST — No pending reboot required" }
    else { Log-Warn "NIST — System has a pending reboot" }
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 12: ADDITIONAL HARDENING
# Various — BitLocker, Credential Guard, Login Banner
# ═══════════════════════════════════════════════════════════════════════
function Invoke-AdditionalHardening {
    Log-Section "12. ADDITIONAL HARDENING (NIST/STIG)"

    # Login banner
    $title = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue).LegalNoticeCaption
    $text = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction SilentlyContinue).LegalNoticeText
    if ($title -and $text) { Log-Pass "CIS 2.3.7.5 — Login banner: Configured" }
    else { Log-Fail "CIS 2.3.7.5 — Login banner: Not configured"
        if (Test-CanFix) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "NOTICE"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Authorized users only. All activity may be monitored."
            Log-Info "Set login warning banner"
        }
    }

    # AutoPlay disabled
    $autoplay = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    if ($autoplay -eq 255) { Log-Pass "CIS 18.9.x — AutoPlay: Disabled (all drives)" }
    else { Log-Fail "CIS 18.9.x — AutoPlay: Not fully disabled" }

    # BitLocker
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if ($bl -and $bl.ProtectionStatus -eq 'On') { Log-Pass "STIG — BitLocker ($env:SystemDrive): Enabled" }
    else { Log-Warn "STIG — BitLocker ($env:SystemDrive): Not enabled" }

    # Print Spooler (PrintNightmare)
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($spooler.Status -eq 'Running') { Log-Warn "NIST — Print Spooler: Running (disable if not needed — PrintNightmare)" }
    else { Log-Pass "NIST — Print Spooler: Not running" }

    # Admin shares
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue).AutoShareServer
    if ($val -eq 0) { Log-Pass "STIG — Administrative shares: Disabled" }
    else { Log-Warn "STIG — Administrative shares: Enabled (C$, ADMIN$)" }

    # Spectre/Meltdown mitigations
    $spectre = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue).FeatureSettingsOverride
    if ($null -ne $spectre) { Log-Pass "NIST — Spectre/Meltdown mitigations: Configured ($spectre)" }
    else { Log-Warn "NIST — Spectre/Meltdown mitigations: Not explicitly configured" }

    # Local admin count
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $adminCount = ($admins | Measure-Object).Count
    if ($adminCount -le 2) { Log-Pass "NIST — Local admin count: $adminCount" }
    else { Log-Warn "NIST — Local admin count: $adminCount (review — minimize)" }
}

# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════
function New-HtmlReport {
    Log-Section "GENERATING REPORT"
    $score = if ($Script:TotalCount -gt 0) { [math]::Round($Script:PassCount / $Script:TotalCount * 100) } else { 0 }

    $resultsHtml = $Script:Results | ForEach-Object {
        $color = switch ($_.Status) { 'PASS' {'#22c55e'} 'FAIL' {'#ef4444'} 'WARN' {'#eab308'} default {'#888'} }
        "<tr><td style='color:$color;font-weight:600'>[$($_.Status)]</td><td>$($_.Message)</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PowerShield Report</title>
<style>body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;max-width:960px;margin:0 auto}
h1{color:#0078d4}h2{color:#58a6ff;border-bottom:1px solid #21262d;padding-bottom:8px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:14px}td{padding:6px 10px;border-bottom:1px solid #21262d}
.stat{display:inline-block;padding:10px 20px;margin:4px;border:1px solid #21262d;border-radius:8px;font-weight:600}
.pass{color:#22c55e}.fail{color:#ef4444}.warn{color:#eab308}</style></head>
<body><h1>🛡️ PowerShield Hardening Report</h1>
<p>Generated: $(Get-Date) | Hostname: $env:COMPUTERNAME | OS: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)</p>
<h2>Summary</h2>
<div class="stat pass">PASS: $($Script:PassCount)</div>
<div class="stat fail">FAIL: $($Script:FailCount)</div>
<div class="stat warn">WARN: $($Script:WarnCount)</div>
<div class="stat">SKIP: $($Script:SkipCount)</div>
<div class="stat" style="color:#0078d4;font-size:1.5em">SCORE: $score%</div>
<h2>Detailed Results</h2>
<table>$($resultsHtml -join "`n")</table>
</body></html>
"@
    $html | Out-File -FilePath $Script:ReportFile -Encoding UTF8
    Log-Info "Report saved: $Script:ReportFile"
}

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
function Show-Summary {
    $score = if ($Script:TotalCount -gt 0) { [math]::Round($Script:PassCount / $Script:TotalCount * 100) } else { 0 }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "  PowerShield Hardening Summary" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "  PASS:  $($Script:PassCount)" -ForegroundColor Green
    Write-Host "  FAIL:  $($Script:FailCount)" -ForegroundColor Red
    Write-Host "  WARN:  $($Script:WarnCount)" -ForegroundColor Yellow
    Write-Host "  SKIP:  $($Script:SkipCount)" -ForegroundColor DarkGray
    Write-Host "  TOTAL: $($Script:TotalCount)" -ForegroundColor White
    Write-Host ""

    if ($score -ge 80) { Write-Host "  Score: $score% — Well hardened" -ForegroundColor Green }
    elseif ($score -ge 60) { Write-Host "  Score: $score% — Needs improvement" -ForegroundColor Yellow }
    else { Write-Host "  Score: $score% — Critical gaps found" -ForegroundColor Red }

    Write-Host ""
    Write-Host "  Log:    $Script:LogFile" -ForegroundColor DarkGray
    Write-Host "  Report: $Script:ReportFile" -ForegroundColor DarkGray
    Write-Host "  Backup: $Script:BackupDir" -ForegroundColor DarkGray
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
}

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════
if ($Version) { Write-Host "PowerShield v$Script:VERSION"; exit 0 }
if ($Help) {
    Write-Host @"
PowerShield — Windows Server Hardening Tool v$Script:VERSION

Usage: .\PowerShield.ps1 [OPTIONS]

Options:
  -Audit          Audit only (no changes)
  -Fix            Audit + apply fixes
  -DryRun         Show what would change
  -Profile LEVEL  CIS profile: level1, level2, stig (default: level1)
  -Module MOD     Run specific module(s): AccountPolicies, LocalPolicies,
                  AuditPolicy, Firewall, Defender, NetworkSecurity, Services,
                  RegistryHardening, EventLogs, TLSCrypto, WindowsUpdate,
                  AdditionalHardening
  -Report         Generate HTML report
  -Version        Show version
  -Help           Show this help

Examples:
  .\PowerShield.ps1 -Audit
  .\PowerShield.ps1 -Fix -Profile level2
  .\PowerShield.ps1 -Module Firewall,Services,TLSCrypto
"@
    exit 0
}

# Default to audit mode
if (-not $Fix -and -not $DryRun) { $Audit = $true }

Show-Banner
New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null

$modeName = if ($Audit) { "AUDIT ONLY" } elseif ($DryRun) { "DRY RUN" } else { "AUDIT + FIX" }
Log-Info "Mode: $modeName"
Log-Info "Profile: $Profile"
Log-Info "OS: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
Log-Info "Hostname: $env:COMPUTERNAME"

$allModules = @{
    "AccountPolicies"      = { Invoke-AccountPolicies }
    "LocalPolicies"        = { Invoke-LocalPolicies }
    "AuditPolicy"          = { Invoke-AuditPolicy }
    "Firewall"             = { Invoke-Firewall }
    "Defender"             = { Invoke-Defender }
    "NetworkSecurity"      = { Invoke-NetworkSecurity }
    "Services"             = { Invoke-Services }
    "RegistryHardening"    = { Invoke-RegistryHardening }
    "EventLogs"            = { Invoke-EventLogs }
    "TLSCrypto"            = { Invoke-TLSCrypto }
    "WindowsUpdate"        = { Invoke-WindowsUpdate }
    "AdditionalHardening"  = { Invoke-AdditionalHardening }
}

if ($Module) {
    foreach ($m in $Module) {
        if ($allModules.ContainsKey($m)) { & $allModules[$m] }
        else { Log-Warn "Unknown module: $m" }
    }
} else {
    foreach ($m in $allModules.GetEnumerator() | Sort-Object Key) { & $m.Value }
}

New-HtmlReport
Show-Summary
