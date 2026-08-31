function Test-StaleAccounts {
    <#
    .SYNOPSIS
    Identifies active accounts that have not logged in recently.
    
    .DESCRIPTION
    Checks the LastLogonDate of enabled accounts against a threshold.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Accounts,
        [int]$DaysInactive = 90
    )
    $threshold = (Get-Date).AddDays(-$DaysInactive)
    $findings = @()

    foreach ($acc in $Accounts) {
        if ([string]::IsNullOrWhiteSpace($acc.Enabled) -or [bool]::Parse($acc.Enabled) -eq $true) {
            if (-not [string]::IsNullOrWhiteSpace($acc.LastLogonDate)) {
                try {
                    $lastLogon = [datetime]::Parse($acc.LastLogonDate)
                    if ($lastLogon -lt $threshold) {
                        $findings += [PSCustomObject]@{
                            Finding = "Stale Account"
                            Severity = "Medium"
                            AccountName = $acc.SamAccountName
                            Details = "Account has not logged on since $($lastLogon.ToString('yyyy-MM-dd')). Threshold is $DaysInactive days."
                        }
                    }
                } catch {}
            }
        }
    }
    return $findings
}
