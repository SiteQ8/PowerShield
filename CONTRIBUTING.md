# Contributing to PowerShield

## Adding Checks

1. Identify the CIS/NIST/STIG control ID
2. Add to the appropriate `Invoke-*` function
3. Use `Log-Pass`, `Log-Fail`, `Log-Warn` for results
4. Wrap fixes in `if (Test-CanFix) { ... }`
5. Always `Backup-Item` before registry changes

## Code Style
- Pure PowerShell 5.1+ (no external modules)
- Use `PSScriptAnalyzer` for linting
- Include control ID in every check message
- Test on Server 2019 and 2022

## Commit Messages
Use: `add:`, `fix:`, `docs:`, `refactor:`, `test:`
