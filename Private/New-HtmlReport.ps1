function New-HtmlReport {
    <#
    .SYNOPSIS
    Generates a dark-themed HTML report from audit findings.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$Findings,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    # Sort findings to ensure Critical > High > Medium > Low (Roughly by sorting severity string, though alphabetical isn't perfect for severity, let's map them)
    $severityMap = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4 }
    $sortedFindings = $Findings | Sort-Object @{Expression={$severityMap[$_.Severity]}}, @{Expression={$_.Finding}}

    $htmlHead = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AD Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #569cd6; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #444; padding: 10px; text-align: left; }
        th { background-color: #333; color: #fff; }
        tr:nth-child(even) { background-color: #252526; }
        .Critical { color: #f44336; font-weight: bold; }
        .High { color: #ff9800; font-weight: bold; }
        .Medium { color: #ffeb3b; font-weight: bold; }
        .Low { color: #4caf50; font-weight: bold; }
        .summary { background-color: #333; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Active Directory Security Audit Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: $($Findings.Count)</p>
        <ul>
            <li>Critical: $(($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count)</li>
            <li>High: $(($Findings | Where-Object { $_.Severity -eq 'High' }).Count)</li>
            <li>Medium: $(($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count)</li>
            <li>Low: $(($Findings | Where-Object { $_.Severity -eq 'Low' }).Count)</li>
        </ul>
    </div>
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Finding</th>
            <th>Account Name</th>
            <th>Details</th>
        </tr>
"@

    $htmlBody = ""
    foreach ($finding in $sortedFindings) {
        $severity = [System.Net.WebUtility]::HtmlEncode([string]$finding.Severity)
        $findingName = [System.Net.WebUtility]::HtmlEncode([string]$finding.Finding)
        $accountName = [System.Net.WebUtility]::HtmlEncode([string]$finding.AccountName)
        $details = [System.Net.WebUtility]::HtmlEncode([string]$finding.Details)
        $htmlBody += @"
        <tr>
            <td class="$severity">$severity</td>
            <td>$findingName</td>
            <td>$accountName</td>
            <td>$details</td>
        </tr>
"@
    }

    $htmlTail = @"
    </table>
</body>
</html>
"@

    $fullHtml = $htmlHead + $htmlBody + $htmlTail
    $fullHtml | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
}
