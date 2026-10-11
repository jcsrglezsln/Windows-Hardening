# Windows Hardening

Assesses Windows security configurations using PowerShell to identify controls that meet security requirements, controls that require attention, and checks that could not be completed.

## Features

The current assessment baseline evaluates:

- **Windows Firewall:** Domain, Private, and Public profiles.
- **Microsoft Defender Antivirus:** Antivirus and real-time protection status.
- **SMBv1:** Protocol feature state.
- **Guest Account:** Enabled or disabled state of the built-in Guest account.
- **Audit Policy:** Six selected security audit subcategories.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell with the required administrative permissions.
- Windows security cmdlets and features required by each assessment module.

Some checks may require elevated permissions or depend on Windows edition and configuration.

## Usage

Run the assessment from the project directory:

```powershell
.\Hardening.ps1 -Assess
```

The report includes the computer name, scan date, overall assessment status, control results, and error messages when available.

## Assessment Status

- **Compliant:** The observed configuration meets the defined requirement.
- **Non-Compliant:** The observed configuration does not meet the requirement.
- **Unknown:** The assessment could not reliably determine compliance.

An assessment failure must not be interpreted as a compliant result.

## Validation

The current development tests include:

- Successful assessment of the three Windows Firewall profiles.
- Verification of Microsoft Defender status.
- Verification of SMBv1 state.
- Identification of the built-in Guest account by its SID, avoiding dependence on localized account names.
- Assessment of audit policies using stable subcategory GUIDs and numeric configuration values.
- Simulated failures to verify that failed checks return `Unknown` and preserve error details.
- Verification that the main script reports control results and calculates the overall status.

These are development checks on the test system, not a claim of comprehensive compatibility testing across all Windows versions or enterprise environments.

## Scope and Safety

The current version performs **assessment only**. It does not intentionally modify the evaluated security configurations.

A future remediation mode will be developed separately, with explicit execution controls and error handling.

## Project Structure

```text
Windows-Hardening/
├── Hardening.ps1
├── Get-FirewallStatus.ps1
├── Get-DefenderStatus.ps1
├── Get-SMBStatus.ps1
├── Get-GuestAccountStatus.ps1
├── Get-AuditPolicyStatus.ps1
└── README.md
```

## Roadmap

- [x] Windows Firewall assessment
- [x] Microsoft Defender assessment
- [x] SMBv1 assessment
- [x] Built-in Guest account assessment
- [x] Audit policy assessment
- [x] Consolidated assessment report
- [ ] Exportable assessment report
- [ ] Controlled remediation mode
- [ ] Post-remediation verification

## License

MIT