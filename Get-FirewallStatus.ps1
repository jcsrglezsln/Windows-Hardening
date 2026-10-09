
function Get-FirewallStatus {

    <#
    .SYNOPSIS
        Checks the status of Windows Firewall profiles.

    .DESCRIPTION
        Retrieves Domain, Private and Public Firewall profiles
        and evaluates compliance. Failed queries return Unknown.

    .OUTPUTS
        PSCustomObject
    #>

    $ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    try {

        $FirewallProfiles = @(
            Get-NetFirewallProfile -ErrorAction Stop
        )

        if ($FirewallProfiles.Count -eq 0) {
            throw "No Firewall profiles were returned."
        }

        foreach ($ProfileName in @("Domain", "Private", "Public")) {

            $Profile = $FirewallProfiles |
                Where-Object Name -eq $ProfileName |
                Select-Object -First 1

            if ($null -eq $Profile -or $null -eq $Profile.Enabled) {

                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    ScanDate     = $ScanDate
                    Profile      = $ProfileName
                    Enabled      = $null
                    Status       = "Unknown"
                    ErrorMessage = "Profile missing or Enabled state unavailable."
                }

                continue
            }

            $Status = if ($Profile.Enabled) {
                "Compliant"
            }
            else {
                "Non-Compliant"
            }

            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                ScanDate     = $ScanDate
                Profile      = $Profile.Name
                Enabled      = [bool]$Profile.Enabled
                Status       = $Status
                ErrorMessage = $null
            }
        }
    }
    catch {

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = $ScanDate
            Profile      = $null
            Enabled      = $null
            Status       = "Unknown"
            ErrorMessage = $_.Exception.Message
        }
    }
}
