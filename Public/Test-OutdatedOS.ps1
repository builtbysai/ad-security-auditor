function Test-OutdatedOS {
    <#
    .SYNOPSIS
    Identifies enabled computer accounts running outdated operating systems.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Computers
    )
    $outdatedPatterns = @("Windows 7", "Windows Server 2008", "Windows XP", "Windows Server 2003", "Windows 8", "Windows Server 2012")
    $findings = @()
    foreach ($comp in $Computers) {
        $isEnabled = [string]::IsNullOrWhiteSpace($comp.Enabled) -or ([bool]::TryParse($comp.Enabled, [ref]$null) -and [bool]::Parse($comp.Enabled))
        if ($isEnabled -and -not [string]::IsNullOrWhiteSpace($comp.OperatingSystem)) {
            foreach ($pattern in $outdatedPatterns) {
                if ($comp.OperatingSystem -match $pattern) {
                    $findings += [PSCustomObject]@{
                        Finding = "Outdated Operating System"
                        Severity = "High"
                        AccountName = $comp.SamAccountName
                        Details = "Computer is running an outdated OS: $($comp.OperatingSystem)"
                    }
                    break
                }
            }
        }
    }
    return $findings
}
