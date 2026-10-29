# Windows Hardening Assessment

A PowerShell-based tool for assessing selected Windows security configurations, identifying compliant and non-compliant controls, and reporting checks whose results could not be reliably determined.

## Features

The current assessment baseline evaluates 12 security controls across five areas:

- **Windows Firewall:** Domain, Private, and Public profiles.
- **Microsoft Defender Antivirus:** Antivirus and real-time protection status.
- **SMBv1:** Protocol feature state.
- **Built-in Guest Account:** Enabled or disabled state, identified by its security identifier (SID).
- **Audit Policy:** Six selected security audit subcategories.

The assessment consolidates individual check results into an overall status and summary counts. Reports can be exported to CSV for further review.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell.
- Appropriate permissions for the security checks being performed.
- Windows security cmdlets and features required by each assessment module.

Some checks may require an elevated PowerShell session. Results may also depend on the Windows edition, system configuration, available features, and permissions.

## Usage

Run the commands from the project directory.

### Run an assessment

```powershell
.\Hardening.ps1 -Assess
```

### Export the assessment to CSV

```powershell
.\Hardening.ps1 -Assess -ExportCsv
```

### Specify a custom output directory

```powershell
.\Hardening.ps1 -Assess -ExportCsv -OutputPath ".\TestReports"
```

The console displays the overall assessment status and the counts of compliant, non-compliant, and unknown controls.

## Assessment Status

Each control is assigned one of the following statuses:

- **Compliant:** The observed configuration meets the defined requirement.
- **Non-Compliant:** The observed configuration does not meet the defined requirement.
- **Unknown:** The assessment could not reliably determine compliance, including when a check fails or returns an invalid result.

An assessment failure must not be interpreted as a compliant result.

The overall assessment status summarizes the individual control results.

## CSV Report Format

The exported CSV contains one summary record followed by one record for each assessed control.

### Summary record

The `Summary` record includes:

- Overall assessment status.
- Compliant control count.
- Non-compliant control count.
- Unknown control count.
- Total number of assessed controls.

### Control records

Each `Control` record includes:

- Computer name.
- Scan date.
- Control name.
- Individual assessment status.
- Error message, when available.

The `RecordType` column distinguishes `Summary` records from `Control` records. Both record types share the same CSV columns; fields that do not apply to a particular record type are left empty.

For the current baseline of 12 controls, a successful report contains 13 data rows: one summary record and 12 control records.

### Example CSV output

The following is an illustrative example of the report structure:

```csv
RecordType,ComputerName,ScanDate,OverallStatus,CompliantCount,NonCompliantCount,UnknownCount,TotalControls,Control,Status,ErrorMessage
Summary,EXAMPLE-PC,2026-10-29 10:00:00,Compliant,12,0,0,12,,,
Control,EXAMPLE-PC,2026-10-29 10:00:00,,,,,,,Firewall Domain,Compliant,
Control,EXAMPLE-PC,2026-10-29 10:00:00,,,,,,,SMBv1,Compliant,
```

The example uses placeholder data and does not represent a complete report or an actual computer name.

## Validation

Development and manual checks have covered the following scenarios:

- Assessment of the three Windows Firewall profiles.
- Verification of Microsoft Defender status.
- Verification of SMBv1 state.
- Identification of the built-in Guest account by SID to avoid dependence on localized account names.
- Assessment of audit policies using subcategory GUIDs and numeric configuration values.
- Simulated check failures, confirming that failed checks return `Unknown` and preserve error details.
- Verification that the main script collects control results and calculates the overall status.
- CSV export using the default output directory.
- CSV export using a custom output directory.
- Invalid output path handling without reporting a false export success.
- Checks that return no results, which must produce an `Unknown` result.
- Results with missing or invalid `Status` values, which must be converted to `Unknown`.
- CSV structure validation for one summary record and 12 control records.

These checks do not constitute comprehensive compatibility testing across all Windows versions, editions, or enterprise environments.

## Scope and Safety

The current version performs **assessment only**. It is designed to inspect selected security configurations and report their observed state; it does not intentionally modify the evaluated configurations.

The tool does not currently implement automated remediation. Any future remediation functionality will be developed separately, with explicit execution controls, error handling, and post-remediation verification.

## Project Structure

```text
Windows-Hardening/
|-- Hardening.ps1
|-- Get-FirewallStatus.ps1
|-- Get-DefenderStatus.ps1
|-- Get-SMBStatus.ps1
|-- Get-GuestAccountStatus.ps1
|-- Get-AuditPolicyStatus.ps1
|-- README.md
```

## Roadmap

- [x] Windows Firewall assessment
- [x] Microsoft Defender assessment
- [x] SMBv1 assessment
- [x] Built-in Guest account assessment
- [x] Audit policy assessment
- [x] Consolidated assessment report
- [x] CSV assessment report export
- [x] Summary record in CSV reports
- [x] Validation of missing and invalid check results
- [ ] Automated test suite
- [ ] Controlled remediation mode
- [ ] Post-remediation verification

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
