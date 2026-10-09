# Windows Hardening

A PowerShell-based Windows security assessment tool that evaluates selected hardening configurations and reports compliance status.

## Overview

Windows Hardening helps administrators identify selected Windows security configuration gaps through a read-only assessment. It provides individual control results, an overall compliance summary, and error details when a control cannot be evaluated.

**Current version:** Assessment-only. No security settings are modified.

## Features

- Windows Firewall profile assessment (Domain, Private, and Public).
- Microsoft Defender Antivirus and real-time protection checks.
- SMBv1 optional feature assessment.
- Built-in Guest account status detection using its security identifier (SID).
- Selected Windows audit policy subcategory assessments using GUIDs and numeric values.
- Overall compliance summary with `Compliant`, `Non-Compliant`, and `Unknown` states.
- Error reporting for failed or incomplete assessments.
- Designed to support Windows installations with different display languages.

## Requirements

- Windows with PowerShell.
- Permissions required to query the selected security settings.
- Windows PowerShell commands and modules available for the assessed features, including `NetSecurity`, Defender cmdlets, local account cmdlets, and Windows optional feature management.
- `auditpol.exe` available for audit policy assessment.

Some checks may require an elevated PowerShell session, depending on the system configuration.

## Usage

Open PowerShell in the project directory and run:

```powershell
.\Hardening.ps1 -Assess
```

The report displays the computer name, scan time, overall status, control counts, and individual assessment results.

## Assessment states

| Status | Meaning |
|---|---|
| `Compliant` | The observed configuration matches the defined expectation. |
| `Non-Compliant` | The observed configuration does not match the defined expectation. |
| `Unknown` | The configuration could not be evaluated reliably. |

An overall `Unknown` status takes precedence when one or more controls cannot be assessed. Otherwise, any non-compliant control makes the overall result `Non-Compliant`.

## Current assessment scope

The initial baseline contains 12 results across five assessment modules:

| Module | Assessment |
|---|---|
| `Get-FirewallStatus.ps1` | Three Windows Firewall profiles |
| `Get-DefenderStatus.ps1` | Antivirus and real-time protection |
| `Get-SMBStatus.ps1` | SMBv1 optional feature state |
| `Get-GuestAccountStatus.ps1` | Built-in Guest account enabled state |
| `Get-AuditPolicyStatus.ps1` | Six selected audit policy subcategories |

The audit policy assessment checks System Integrity, Logon, Account Lockout, Audit Policy Change, Security Group Management, and User Account Management.

These checks represent a selected baseline, not a comprehensive certification of Windows security or compliance with a specific regulatory framework. For example, the SMBv1 check assesses the Windows optional feature state rather than every possible SMB configuration.

## Project structure

```text
Windows-Hardening/
├── Hardening.ps1
├── Get-FirewallStatus.ps1
├── Get-DefenderStatus.ps1
├── Get-SMBStatus.ps1
├── Get-GuestAccountStatus.ps1
├── Get-AuditPolicyStatus.ps1
├── README.md
├── LICENSE
└── .gitignore
```

## Safety

This version performs assessment only. It does not enable or disable Windows Firewall, modify Microsoft Defender settings, change SMB configuration, enable or disable accounts, or alter audit policies.

Always validate security recommendations against organizational requirements before applying changes.

## Roadmap

- Improve assessment coverage and error handling.
- Add structured report export.
- Design a separate, explicitly invoked remediation workflow with safeguards and verification.

## License

This project is distributed under the MIT License. See `LICENSE` for details.