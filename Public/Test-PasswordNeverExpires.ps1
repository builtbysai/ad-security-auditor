function Test-PasswordNeverExpires {
    <#
    .SYNOPSIS
    Identifies enabled user accounts where the password never expires.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Users
    )
    $findings = @()
    foreach ($user in $Users) {
        $isEnabled = [string]::IsNullOrWhiteSpace($user.Enabled) -or ([bool]::TryParse($user.Enabled, [ref]$null) -and [bool]::Parse($user.Enabled))
        $pwdNeverExpires = (-not [string]::IsNullOrWhiteSpace($user.PasswordNeverExpires)) -and ([bool]::TryParse($user.PasswordNeverExpires, [ref]$null) -and [bool]::Parse($user.PasswordNeverExpires))
        
        if ($isEnabled -and $pwdNeverExpires) {
            $findings += [PSCustomObject]@{
                Finding = "Password Never Expires"
                Severity = "High"
                AccountName = $user.SamAccountName
                Details = "Enabled account has 'Password Never Expires' set to True."
            }
        }
    }
    return $findings
}
