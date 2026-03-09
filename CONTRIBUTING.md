# Contributing to PowerShield

## Adding Security Checks

1. Identify the applicable CIS, NIST, or STIG control identifier.
2. Add the check to the appropriate `Invoke-*` function in `PowerShield.ps1`.
3. Use the standardized logging functions: `Log-Pass`, `Log-Fail`, `Log-Warn`, `Log-Skip`.
4. Wrap all remediation logic in `if (Test-CanFix) { ... }`.
5. Call `Backup-Item` before modifying any registry key or configuration file.
6. Include the control ID in the log message (e.g., "CIS 1.1.4 — Min password length: 14").

## Code Standards

- Pure PowerShell 5.1+ — no external modules or dependencies.
- Use `PSScriptAnalyzer` for static analysis before submitting.
- All checks must include a standards reference (CIS, NIST, STIG).
- Test on both Windows Server 2019 and 2022.
- Follow the existing naming conventions for functions and variables.

## Testing

```powershell
# Static analysis
Install-Module PSScriptAnalyzer -Force
Invoke-ScriptAnalyzer -Path .\PowerShield.ps1 -Severity Error,Warning

# Syntax validation
$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content .\PowerShield.ps1 -Raw), [ref]$null)

# Audit mode (read-only, safe for any environment)
.\PowerShield.ps1 -Audit
```

## Commit Messages

Use conventional format: `add:`, `fix:`, `docs:`, `refactor:`, `test:`

## Submission Process

1. Fork the repository.
2. Create a feature branch from `main`.
3. Implement and test changes.
4. Submit a pull request with a clear description of the changes and applicable control IDs.
