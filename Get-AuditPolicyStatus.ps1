
function Get-AuditPolicyStatus {

    <#
    .SYNOPSIS
        Checks selected Windows audit policy subcategories.

    .DESCRIPTION
        Evaluates audit policy settings using stable subcategory GUIDs
        and numeric configuration values. Failed queries return Unknown.

    .OUTPUTS
        PSCustomObject
    #>

    $ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $AuditPolicies = @(
        @{
            Name = "System Integrity"
            GUID = "{0CCE9212-69AE-11D9-BED3-505054503030}"
            ExpectedValue = 3
        },
        @{
            Name = "Logon"
            GUID = "{0CCE9215-69AE-11D9-BED3-505054503030}"
            ExpectedValue = 3
        },
        @{
            Name = "Account Lockout"
            GUID = "{0CCE9217-69AE-11D9-BED3-505054503030}"
            ExpectedValue = 1
        },
        @{
            Name = "Audit Policy Change"
            GUID = "{0CCE922F-69AE-11D9-BED3-505054503030}"
            ExpectedValue = 1
        },
        @{
            Name = "Security Group Management"
            GUID = "{0CCE9237-69AE-11D9-BED3-505054503030}"
            ExpectedValue = 1
        },
        @{
            Name = "User Account Management"
            GUID = "{0CCE9235-69AE-11D9-BED3-505054503030}"
            ExpectedValue = 1
        }
    )

    $AuditFile = Join-Path $env:TEMP (
        "Windows-Hardening-AuditPolicy-$PID.csv"
    )

    try {

        & auditpol.exe /backup "/file:$AuditFile" | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "auditpol backup failed with exit code $LASTEXITCODE."
        }

        if (-not (Test-Path -LiteralPath $AuditFile -PathType Leaf)) {
            throw "Audit policy backup file was not created."
        }

        $AuditData = @(Import-Csv -LiteralPath $AuditFile -ErrorAction Stop)

        if ($AuditData.Count -eq 0) {
            throw "Audit policy backup contains no records."
        }

        foreach ($Policy in $AuditPolicies) {

            $AuditRecord = @(
                $AuditData | Where-Object {
                    @($_.PSObject.Properties.Value) -contains $Policy.GUID
                }
            ) | Select-Object -First 1

            if ($null -eq $AuditRecord) {

                [PSCustomObject]@{
                    ComputerName   = $env:COMPUTERNAME
                    ScanDate       = $ScanDate
                    Policy         = $Policy.Name
                    GUID           = $Policy.GUID
                    CurrentValue   = $null
                    ExpectedValue  = $Policy.ExpectedValue
                    CurrentSetting = $null
                    Status         = "Unknown"
                    ErrorMessage   = "Audit subcategory was not found in the backup."
                }

                continue
            }
            # Find the numeric audit value without depending on
            # localized CSV column names.
            $ValueProperty = $AuditRecord.PSObject.Properties |
                Where-Object {
                    $_.Value -is [string] -and
                    $_.Value -match '^[0-3]$'
                } |
                Select-Object -Last 1

            $SettingProperty = $AuditRecord.PSObject.Properties |
                Where-Object {
                    $_.Value -in @(
                        "Sin auditoría",
                        "Aciertos",
                        "Errores",
                        "Aciertos y errores",
                        "No Auditing",
                        "Success",
                        "Failure",
                        "Success and Failure"
                    )
                } |
                Select-Object -First 1

            $CurrentValue = $null
            $ValueIsValid = (
                $null -ne $ValueProperty -and
                [int]::TryParse(
                    [string]$ValueProperty.Value,
                    [ref]$CurrentValue
                )
            )

            if (
                $ValueIsValid -and
                ($CurrentValue -lt 0 -or $CurrentValue -gt 3)
            ) {
                $ValueIsValid = $false
            }

            if (-not $ValueIsValid) {

                [PSCustomObject]@{
                    ComputerName   = $env:COMPUTERNAME
                    ScanDate       = $ScanDate
                    Policy         = $Policy.Name
                    GUID           = $Policy.GUID
                    CurrentValue   = $null
                    ExpectedValue  = $Policy.ExpectedValue
                    CurrentSetting = if ($SettingProperty) {
                        $SettingProperty.Value
                    } else {
                        $null
                    }
                    Status         = "Unknown"
                    ErrorMessage   = "Audit configuration value is missing or invalid."
                }

                continue
            }

            $Status = if ($CurrentValue -eq $Policy.ExpectedValue) {
                "Compliant"
            }
            else {
                "Non-Compliant"
            }

            [PSCustomObject]@{
                ComputerName   = $env:COMPUTERNAME
                ScanDate       = $ScanDate
                Policy         = $Policy.Name
                GUID           = $Policy.GUID
                CurrentValue   = $CurrentValue
                ExpectedValue  = $Policy.ExpectedValue
                CurrentSetting = if ($SettingProperty) {
                    $SettingProperty.Value
                } else {
                    $null
                }
                Status         = $Status
                ErrorMessage   = $null
            }
        }
    }
    catch {

        $ErrorMessage = $_.Exception.Message

        foreach ($Policy in $AuditPolicies) {

            [PSCustomObject]@{
                ComputerName   = $env:COMPUTERNAME
                ScanDate       = $ScanDate
                Policy         = $Policy.Name
                GUID           = $Policy.GUID
                CurrentValue   = $null
                ExpectedValue  = $Policy.ExpectedValue
                CurrentSetting = $null
                Status         = "Unknown"
                ErrorMessage   = $ErrorMessage
            }
        }
    }
    finally {

        Remove-Item -LiteralPath $AuditFile `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
