
param(
    [switch]$Assess
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
        @(& $Check)
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

        $Properties = $Result.PSObject.Properties


        $Control = "Unknown Control"

        if ($Result.PSObject.Properties.Name -contains "Control") {
            $Control = $Result.Control
        }
        elseif (
            $Result.PSObject.Properties.Name -contains "Profile" -and
            -not [string]::IsNullOrWhiteSpace($Result.Profile)
        ) {
            $Control = "Firewall - $($Result.Profile)"
        }
        elseif ($Result.PSObject.Properties.Name -contains "AntivirusEnabled") {
            $Control = "Microsoft Defender"
        }
        elseif ($Result.PSObject.Properties.Name -contains "SMBv1Enabled") {
            $Control = "SMBv1"
        }
        elseif ($Result.PSObject.Properties.Name -contains "AccountSID") {
            $Control = "Guest Account"
        }
        elseif ($Result.PSObject.Properties.Name -contains "Policy") {
            $Control = "Audit - $($Result.Policy)"
        }


        [PSCustomObject]@{
            Control      = $Control
            Status       = $Result.Status
            ErrorMessage = $Result.ErrorMessage
        }
    }

    $Report | Format-Table Control, Status, ErrorMessage -AutoSize -Wrap

}
else {

    Write-Host "Windows Hardening" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Hardening.ps1 -Assess"
    Write-Host ""
}
