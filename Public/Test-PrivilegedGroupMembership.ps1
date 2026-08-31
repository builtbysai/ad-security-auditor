function Test-PrivilegedGroupMembership {
    <#
    .SYNOPSIS
    Checks for unapproved members in privileged groups and disabled accounts in privileged groups.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Users,
        [array]$PrivilegedGroups = @("Domain Admins", "Enterprise Admins"),
        [array]$AllowedUsers = @("Administrator", "jsmith", "svc_sql")
    )
    $findings = @()
    foreach ($user in $Users) {
        if ([string]::IsNullOrWhiteSpace($user.MemberOf)) { continue }
        
        $memberOf = $user.MemberOf -split ';'
        $isPrivileged = $false
        $foundGroups = @()
        
        foreach ($group in $memberOf) {
            foreach ($priv in $PrivilegedGroups) {
                if ($group -match "CN=$priv,") {
                    $isPrivileged = $true
                    $foundGroups += $priv
                }
            }
        }
        
        if ($isPrivileged) {
            $isEnabled = [string]::IsNullOrWhiteSpace($user.Enabled) -or ([bool]::TryParse($user.Enabled, [ref]$null) -and [bool]::Parse($user.Enabled))
            
            $foundGroupsStr = ($foundGroups | Select-Object -Unique) -join ', '
            
            if (-not $isEnabled) {
                $findings += [PSCustomObject]@{
                    Finding = "Disabled Account in Privileged Group"
                    Severity = "High"
                    AccountName = $user.SamAccountName
                    Details = "Disabled account is a member of: $foundGroupsStr"
                }
            } elseif ($user.SamAccountName -notin $AllowedUsers) {
                $findings += [PSCustomObject]@{
                    Finding = "Unapproved Privileged User"
                    Severity = "Critical"
                    AccountName = $user.SamAccountName
                    Details = "User is in privileged group(s) ($foundGroupsStr) but not in allowlist."
                }
            }
        }
    }
    return $findings
}
