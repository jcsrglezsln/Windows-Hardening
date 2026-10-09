
function Get-DefenderStatus {

    <#
    .SYNOPSIS
        Checks Microsoft Defender Antivirus status.

    .DESCRIPTION
        Evaluates antivirus and real-time protection status.
        Failed queries return Unknown instead of a false compliance result.

    .OUTPUTS
        PSCustomObject
    #>

    $ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    try {

        $Defender = Get-MpComputerStatus -ErrorAction Stop

        if (
            $null -eq $Defender -or
            $null -eq $Defender.AntivirusEnabled -or
            $null -eq $Defender.RealTimeProtectionEnabled
        ) {
            throw "Defender returned incomplete status information."
        }

        if (
            $Defender.AntivirusEnabled -and
            $Defender.RealTimeProtectionEnabled
        ) {
            $Status = "Compliant"
        }
        else {
            $Status = "Non-Compliant"
        }

        [PSCustomObject]@{
            ComputerName              = $env:COMPUTERNAME
            ScanDate                  = $ScanDate
            AntivirusEnabled          = $Defender.AntivirusEnabled
            RealTimeProtectionEnabled = $Defender.RealTimeProtectionEnabled
            Status                    = $Status
            ErrorMessage              = $null
        }
    }
    catch {

        [PSCustomObject]@{
            ComputerName              = $env:COMPUTERNAME
            ScanDate                  = $ScanDate
            AntivirusEnabled          = $null
            RealTimeProtectionEnabled = $null
            Status                    = "Unknown"
            ErrorMessage              = $_.Exception.Message
        }
    }
}
