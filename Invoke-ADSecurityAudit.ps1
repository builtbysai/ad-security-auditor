<#
.SYNOPSIS
Main execution script for AD Security Auditor.

.DESCRIPTION
Loads check functions, runs them against provided CSV data, and generates reports.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$UsersCsv,
    [Parameter(Mandatory=$true)]
    [string]$GroupsCsv,
    [Parameter(Mandatory=$true)]
    [string]$ComputersCsv,
    [string]$ReportFolder = ".\Reports"
)

# Load functions
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Get-ChildItem -Path (Join-Path $scriptPath "Public") -Filter "*.ps1" | ForEach-Object { . $_.FullName }
Get-ChildItem -Path (Join-Path $scriptPath "Private") -Filter "*.ps1" | ForEach-Object { . $_.FullName }

if (-not (Test-Path $ReportFolder)) {
    New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
}

Write-Host "Loading data..."
$users = Import-Csv -Path $UsersCsv
$groups = Import-Csv -Path $GroupsCsv
$computers = Import-Csv -Path $ComputersCsv

$allFindings = @()

Write-Host "Running tests..."
$allFindings += Test-StaleAccounts -Accounts $users -DaysInactive 90
$allFindings += Test-StaleAccounts -Accounts $computers -DaysInactive 90
$allFindings += Test-PasswordNeverExpires -Users $users
$allFindings += Test-OldPasswordAge -Users $users -MaxPasswordAgeDays 365
$allFindings += Test-PrivilegedGroupMembership -Users $users
$allFindings += Test-OutdatedOS -Computers $computers
$allFindings += Test-DuplicateSPNs -Users $users -Computers $computers

if ($allFindings.Count -eq 0) {
    Write-Host "No findings discovered."
} else {
    Write-Host "Discovered $($allFindings.Count) findings."
}

Write-Host "Generating reports..."
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$csvPath = Join-Path $ReportFolder "AuditFindings_$timestamp.csv"
$allFindings | Export-Csv -Path $csvPath -NoTypeInformation

$jsonPath = Join-Path $ReportFolder "AuditFindings_$timestamp.json"
$allFindings | ConvertTo-Json | Out-File -FilePath $jsonPath -Encoding UTF8

$htmlPath = Join-Path $ReportFolder "AuditFindings_$timestamp.html"
New-HtmlReport -Findings $allFindings -OutputPath $htmlPath

Write-Host "Audit complete. Reports saved to $ReportFolder"
