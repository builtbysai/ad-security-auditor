function Test-OldPasswordAge {
    <#
    .SYNOPSIS
    Identifies enabled user accounts with passwords older than the specified threshold.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Users,
        [int]$MaxPasswordAgeDays = 365
    )
    $threshold = (Get-Date).AddDays(-$MaxPasswordAgeDays)
    $findings = @()
    foreach ($user in $Users) {
        $isEnabled = [string]::IsNullOrWhiteSpace($user.Enabled) -or ([bool]::TryParse($user.Enabled, [ref]$null) -and [bool]::Parse($user.Enabled))
        if ($isEnabled -and -not [string]::IsNullOrWhiteSpace($user.PasswordLastSet)) {
            try {
                $pwdLastSet = [datetime]::Parse($user.PasswordLastSet)
                if ($pwdLastSet -lt $threshold) {
                    $findings += [PSCustomObject]@{
                        Finding = "Old Password Age"
                        Severity = "Medium"
                        AccountName = $user.SamAccountName
                        Details = "Password last set on $($pwdLastSet.ToString('yyyy-MM-dd')) (>$MaxPasswordAgeDays days ago)."
                    }
                }
            } catch {}
        }
    }
    return $findings
}
