
function Get-SMBStatus {

    <#
    .SYNOPSIS
        Checks SMBv1 protocol status.

    .DESCRIPTION
        Retrieves the SMBv1 optional feature state and evaluates compliance.
        Failed queries or unexpected states return Unknown.

    .OUTPUTS
        PSCustomObject
    #>

    $ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    try {

        $SMB = Get-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol `
            -ErrorAction Stop

        if ($null -eq $SMB -or $null -eq $SMB.State) {
            throw "SMBv1 feature state could not be determined."
        }

        $Enabled = $SMB.State -eq "Enabled"

        if ($SMB.State -eq "Disabled") {
            $Status = "Compliant"
        }
        elseif ($SMB.State -eq "Enabled") {
            $Status = "Non-Compliant"
        }
        else {
            $Status = "Unknown"
        }

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = $ScanDate
            SMBv1Enabled = $Enabled
            FeatureState = $SMB.State
            Status       = $Status
            ErrorMessage = $null
        }
    }
    catch {

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = $ScanDate
            SMBv1Enabled = $null
            FeatureState = $null
            Status       = "Unknown"
            ErrorMessage = $_.Exception.Message
        }
    }
}
