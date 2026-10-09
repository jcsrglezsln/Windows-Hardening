
function Get-GuestAccountStatus {

    <#
    .SYNOPSIS
        Checks the status of the built-in Guest account.

    .DESCRIPTION
        Identifies the built-in Guest account by its well-known SID
        and evaluates whether the account is disabled.
        Failed queries return Unknown.

    .OUTPUTS
        PSCustomObject
    #>

    $ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    try {

        $LocalUsers = @(Get-LocalUser -ErrorAction Stop)

        $GuestAccount = @(
            $LocalUsers | Where-Object {
                $_.SID.Value -match "-501$"
            }
        ) | Select-Object -First 1

        if ($null -eq $GuestAccount) {
            throw "The built-in Guest account could not be identified."
        }

        if ($null -eq $GuestAccount.Enabled) {
            throw "The Guest account enabled state could not be determined."
        }

        if ($GuestAccount.Enabled) {
            $Status = "Non-Compliant"
        }
        else {
            $Status = "Compliant"
        }

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = $ScanDate
            AccountName  = $GuestAccount.Name
            AccountSID   = $GuestAccount.SID.Value
            Enabled      = [bool]$GuestAccount.Enabled
            Status       = $Status
            ErrorMessage = $null
        }
    }
    catch {

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ScanDate     = $ScanDate
            AccountName  = $null
            AccountSID   = $null
            Enabled      = $null
            Status       = "Unknown"
            ErrorMessage = $_.Exception.Message
        }
    }
}
