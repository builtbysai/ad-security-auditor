function Test-DuplicateSPNs {
    <#
    .SYNOPSIS
    Identifies duplicate Service Principal Names (SPNs) across accounts.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Users,
        [Parameter(Mandatory=$true)]
        [array]$Computers
    )
    $findings = @()
    $allSPNs = @{}
    
    $allAccounts = @()
    if ($Users) { $allAccounts += $Users }
    if ($Computers) { $allAccounts += $Computers }
    
    foreach ($acc in $allAccounts) {
        if (-not [string]::IsNullOrWhiteSpace($acc.ServicePrincipalNames)) {
            $spns = $acc.ServicePrincipalNames -split ';' | Where-Object { $_ -ne "" }
            foreach ($spn in $spns) {
                if (-not $allSPNs.ContainsKey($spn)) {
                    $allSPNs[$spn] = @($acc.SamAccountName)
                } else {
                    $allSPNs[$spn] += $acc.SamAccountName
                }
            }
        }
    }
    
    foreach ($spn in $allSPNs.Keys) {
        if ($allSPNs[$spn].Count -gt 1) {
            $findings += [PSCustomObject]@{
                Finding = "Duplicate SPN"
                Severity = "Critical"
                AccountName = ($allSPNs[$spn] -join ', ')
                Details = "The SPN '$spn' is registered to multiple accounts."
            }
        }
    }
    return $findings
}
