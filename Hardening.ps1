
param(
    [switch]$Assess,

    [switch]$ExportCsv,

    [string]$OutputPath = ".\Reports"
)

$ErrorActionPreference = "Stop"

# Load assessment modules.
. "$PSScriptRoot\Get-FirewallStatus.ps1"
. "$PSScriptRoot\Get-DefenderStatus.ps1"
. "$PSScriptRoot\Get-SMBStatus.ps1"
. "$PSScriptRoot\Get-GuestAccountStatus.ps1"
. "$PSScriptRoot\Get-AuditPolicyStatus.ps1"


function Invoke-HardeningCheck {

    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Check
    )

    try {
        $CheckResults = @(& $Check)

        if ($CheckResults.Count -eq 0) {
            return [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                ScanDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Control      = $Name
                Status       = "Unknown"
                ErrorMessage = "The check returned no results."
            }
        }

        foreach ($Result in $CheckResults) {
            $ValidStatuses = @(
                "Compliant",
                "Non-Compliant",
                "Unknown"
            )

            $HasStatusProperty = (
                $null -ne $Result -and
                $null -ne $Result.PSObject.Properties["Status"]
            )

            $ValidStatus = (
                $HasStatusProperty -and
                $Result.Status -is [string] -and
                $Result.Status -in $ValidStatuses
            )

            if (-not $ValidStatus) {
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    ScanDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Control      = $Name
                    Status       = "Unknown"
                    ErrorMessage = "The check returned an invalid result or missing/invalid Status."
                }

                continue
            }

            $Result
        }
    }
    catch {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Control      = $Name
            Status       = "Unknown"
            ErrorMessage = $_.Exception.Message
        }
    }
}

function Get-HardeningAssessment {

    $Results = @()

    $Results += Invoke-HardeningCheck `
        -Name "Firewall" `
        -Check { Get-FirewallStatus }

    $Results += Invoke-HardeningCheck `
        -Name "Microsoft Defender" `
        -Check { Get-DefenderStatus }

    $Results += Invoke-HardeningCheck `
        -Name "SMBv1" `
        -Check { Get-SMBStatus }

    $Results += Invoke-HardeningCheck `
        -Name "Guest Account" `
        -Check { Get-GuestAccountStatus }

    $Results += Invoke-HardeningCheck `
        -Name "Audit Policy" `
        -Check { Get-AuditPolicyStatus }

    return $Results
}


if ($Assess) {

    $Results = @(Get-HardeningAssessment)

    $Compliant = @(
        $Results | Where-Object Status -eq "Compliant"
    ).Count

    $NonCompliant = @(
        $Results | Where-Object Status -eq "Non-Compliant"
    ).Count

    $Unknown = @(
        $Results | Where-Object Status -eq "Unknown"
    ).Count

    $OverallStatus = if ($Unknown -gt 0) {
        "Unknown"
    }
    elseif ($NonCompliant -gt 0) {
        "Non-Compliant"
    }
    else {
        "Compliant"
    }

    Write-Host ""
    Write-Host "Windows Hardening Assessment" -ForegroundColor Cyan
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Scan date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""

    $StatusColor = switch ($OverallStatus) {
        "Compliant"     { "Green" }
        "Non-Compliant" { "Red" }
        default         { "Yellow" }
    }

    Write-Host "Overall status: $OverallStatus" -ForegroundColor $StatusColor
    Write-Host "Compliant:     $Compliant"
    Write-Host "Non-compliant: $NonCompliant"
    Write-Host "Unknown:       $Unknown"
    Write-Host ""


    $Report = foreach ($Result in $Results) {

        $Control = if ($Result.PSObject.Properties["Profile"]) {
            if ([string]::IsNullOrWhiteSpace([string]$Result.Profile)) {
                "Firewall"
            }
            else {
                "Firewall - $($Result.Profile)"
            }
        }
        elseif ($Result.PSObject.Properties["AntivirusEnabled"]) {
            "Microsoft Defender"
        }
        elseif ($Result.PSObject.Properties["SMBv1Enabled"]) {
            "SMBv1"
        }
        elseif ($Result.PSObject.Properties["AccountName"]) {
            "Guest Account"
        }
        elseif ($Result.PSObject.Properties["Policy"]) {
            "Audit - $($Result.Policy)"
        }
        else {
            "Unknown Control"
        }

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = $Result.ScanDate
            Control      = $Control
            Status       = $Result.Status
            ErrorMessage = $Result.ErrorMessage
        }
    }


    $Report | Format-Table Control, Status, ErrorMessage -AutoSize -Wrap

    if ($ExportCsv) {

        try {
            $ResolvedOutputPath = $ExecutionContext.SessionState.Path.
                GetUnresolvedProviderPathFromPSPath($OutputPath)

            if (-not (Test-Path -LiteralPath $ResolvedOutputPath -PathType Container)) {
                New-Item -Path $ResolvedOutputPath -ItemType Directory -Force -ErrorAction Stop |
                    Out-Null
            }

            $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $FileName = "HardeningReport_${env:COMPUTERNAME}_$Timestamp.csv"
            $CsvPath = Join-Path -Path $ResolvedOutputPath -ChildPath $FileName


            $SummaryRecord = [PSCustomObject]@{
                RecordType      = "Summary"
                ComputerName    = $env:COMPUTERNAME
                ScanDate        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                OverallStatus   = $OverallStatus
                CompliantCount  = $Compliant
                NonCompliantCount = $NonCompliant
                UnknownCount    = $Unknown
                TotalControls   = $Results.Count
                Control         = $null
                Status          = $null
                ErrorMessage    = $null
            }

            $ControlRecords = foreach ($Item in $Report) {
                [PSCustomObject]@{
                    RecordType        = "Control"
                    ComputerName      = $Item.ComputerName
                    ScanDate          = $Item.ScanDate
                    OverallStatus     = $null
                    CompliantCount    = $null
                    NonCompliantCount = $null
                    UnknownCount      = $null
                    TotalControls     = $null
                    Control           = $Item.Control
                    Status            = $Item.Status
                    ErrorMessage      = $Item.ErrorMessage
                }
            }

            $CsvRecords = @($SummaryRecord) + @($ControlRecords)

            $CsvRecords | Export-Csv -LiteralPath $CsvPath `
                -NoTypeInformation `
                -Encoding UTF8 `
                -ErrorAction Stop


            Write-Host ""
            Write-Host "CSV report exported successfully:" -ForegroundColor Green
            Write-Host $CsvPath
        }
        catch {
            Write-Host ""
            Write-Host "CSV export failed." -ForegroundColor Red
            Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Red
        }
    }



}
else {

    Write-Host "Windows Hardening" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Hardening.ps1 -Assess"
    Write-Host ""
}
