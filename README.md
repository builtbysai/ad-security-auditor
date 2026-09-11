# AD Security Auditor

A PowerShell 5.1-compatible toolkit designed to audit Active Directory security posture from exported data (CSV/JSON). This tool runs entirely offline without requiring a live domain connection, making it perfect for analyzing exported datasets or demonstrating AD security auditing concepts.

## Features
- **Read-Only Auditing:** Analyzes offline data exports. Does not connect to or modify a live Active Directory environment.
- **Modular Checks:** Includes separate, testable functions for identifying various security risks:
  - Stale or inactive user and computer accounts (no logon in 90+ days).
  - Accounts with "Password Never Expires" set.
  - Accounts with excessively old password ages.
  - Disabled accounts that are still members of privileged groups.
  - Unexpected or unapproved members in Domain Admins or Enterprise Admins.
  - Computers running outdated Operating Systems (e.g., Windows 7, Server 2008).
  - Duplicate or stale Service Principal Names (SPNs).
- **Rich Reporting:** Generates a clean, self-contained, dark-themed HTML report summarizing findings by severity, as well as raw CSV/JSON exports for further analysis.
- **Test Suite:** Includes comprehensive Pester tests to ensure the logic works properly.

## Requirements
- Windows PowerShell 5.1
- [Pester](https://pester.dev/) (For running tests)

## Usage

### 1. Data Export (From a Live AD Environment)
Export your AD objects to CSV. The scripts expect output similar to what `Get-ADUser`, `Get-ADGroup`, and `Get-ADComputer` provide when selecting `*` properties.

Example commands for a live environment:
```powershell
Get-ADUser -Filter * -Properties * | Export-Csv -Path users.csv -NoTypeInformation
Get-ADGroup -Filter * -Properties * | Export-Csv -Path groups.csv -NoTypeInformation
Get-ADComputer -Filter * -Properties * | Export-Csv -Path computers.csv -NoTypeInformation
```

### 2. Running the Audit
Run the main script and point it to your exported CSVs:

```powershell
.\Invoke-ADSecurityAudit.ps1 -UsersCsv ".\SampleData\users.csv" -GroupsCsv ".\SampleData\groups.csv" -ComputersCsv ".\SampleData\computers.csv" -ReportFolder ".\Reports"
```

This will analyze the provided data and generate the HTML, JSON, and CSV reports in the specified output folder.

## Synthetic Sample Dataset
This repository includes a synthetic sample dataset in the `SampleData` folder. It contains fake users, groups, and computers with a mix of clean entries and deliberately planted security issues. You can use this dataset to test the tool immediately.

## Running Tests
To run the included test suite, navigate to the project directory and invoke Pester:

```powershell
Invoke-Pester -Path .\Tests\
```

## License
MIT License

---

*Built by [Hans Sai](https://builtbysai.com).*
