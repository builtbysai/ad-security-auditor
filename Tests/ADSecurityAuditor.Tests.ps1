$publicFolder = Join-Path $PSScriptRoot "..\Public"
Get-ChildItem $publicFolder -Filter "*.ps1" | ForEach-Object { . $_.FullName }

Describe "Test-StaleAccounts" {
    It "Flags accounts older than threshold" {
        $accounts = @(
            [PSCustomObject]@{ SamAccountName = "stale_user"; Enabled = "True"; LastLogonDate = (Get-Date).AddDays(-100).ToString('yyyy-MM-dd HH:mm:ss') }
        )
        $result = @(Test-StaleAccounts -Accounts $accounts)
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Stale Account"
    }

    It "Ignores accounts newer than threshold" {
        $accounts = @(
            [PSCustomObject]@{ SamAccountName = "active_user"; Enabled = "True"; LastLogonDate = (Get-Date).AddDays(-10).ToString('yyyy-MM-dd HH:mm:ss') }
        )
        $result = @(Test-StaleAccounts -Accounts $accounts)
        $result.Count | Should Be 0
    }
}

Describe "Test-PasswordNeverExpires" {
    It "Flags enabled accounts with PasswordNeverExpires set to True" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "bad_user"; Enabled = "True"; PasswordNeverExpires = "True" }
        )
        $result = @(Test-PasswordNeverExpires -Users $users)
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Password Never Expires"
    }

    It "Ignores enabled accounts with PasswordNeverExpires set to False" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "good_user"; Enabled = "True"; PasswordNeverExpires = "False" }
        )
        $result = @(Test-PasswordNeverExpires -Users $users)
        $result.Count | Should Be 0
    }

    It "Ignores disabled accounts with PasswordNeverExpires set to True" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "disabled_user"; Enabled = "False"; PasswordNeverExpires = "True" }
        )
        $result = @(Test-PasswordNeverExpires -Users $users)
        $result.Count | Should Be 0
    }
}

Describe "Test-OldPasswordAge" {
    It "Flags accounts with passwords older than threshold" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "old_pwd_user"; Enabled = "True"; PasswordLastSet = (Get-Date).AddDays(-400).ToString('yyyy-MM-dd HH:mm:ss') }
        )
        $result = @(Test-OldPasswordAge -Users $users -MaxPasswordAgeDays 365)
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Old Password Age"
    }

    It "Ignores accounts with recent passwords" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "recent_pwd_user"; Enabled = "True"; PasswordLastSet = (Get-Date).AddDays(-100).ToString('yyyy-MM-dd HH:mm:ss') }
        )
        $result = @(Test-OldPasswordAge -Users $users -MaxPasswordAgeDays 365)
        $result.Count | Should Be 0
    }
}

Describe "Test-PrivilegedGroupMembership" {
    It "Flags unapproved privileged users" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "hacker"; Enabled = "True"; MemberOf = "CN=Domain Admins,CN=Users,DC=example,DC=local" }
        )
        $result = @(Test-PrivilegedGroupMembership -Users $users -AllowedUsers @("Administrator"))
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Unapproved Privileged User"
    }

    It "Ignores approved privileged users" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "Administrator"; Enabled = "True"; MemberOf = "CN=Domain Admins,CN=Users,DC=example,DC=local" }
        )
        $result = @(Test-PrivilegedGroupMembership -Users $users -AllowedUsers @("Administrator"))
        $result.Count | Should Be 0
    }

    It "Flags disabled accounts in privileged groups" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "old_admin"; Enabled = "False"; MemberOf = "CN=Enterprise Admins,CN=Users,DC=example,DC=local" }
        )
        $result = @(Test-PrivilegedGroupMembership -Users $users -AllowedUsers @("Administrator"))
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Disabled Account in Privileged Group"
    }
}

Describe "Test-OutdatedOS" {
    It "Flags computers running outdated OS" {
        $computers = @(
            [PSCustomObject]@{ SamAccountName = "PC1$"; Enabled = "True"; OperatingSystem = "Windows 7 Professional" }
        )
        $result = @(Test-OutdatedOS -Computers $computers)
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Outdated Operating System"
    }

    It "Ignores computers running modern OS" {
        $computers = @(
            [PSCustomObject]@{ SamAccountName = "PC2$"; Enabled = "True"; OperatingSystem = "Windows Server 2022 Datacenter" }
        )
        $result = @(Test-OutdatedOS -Computers $computers)
        $result.Count | Should Be 0
    }
}

Describe "Test-DuplicateSPNs" {
    It "Flags duplicate SPNs" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "svc_sql1"; ServicePrincipalNames = "MSSQLSvc/db01:1433" }
        )
        $computers = @(
            [PSCustomObject]@{ SamAccountName = "DB01$"; ServicePrincipalNames = "MSSQLSvc/db01:1433;HOST/DB01" }
        )
        $result = @(Test-DuplicateSPNs -Users $users -Computers $computers)
        $result.Count | Should Be 1
        $result[0].Finding | Should Be "Duplicate SPN"
        $result[0].AccountName | Should Match "svc_sql1"
        $result[0].AccountName | Should Match "DB01"
    }

    It "Ignores unique SPNs" {
        $users = @(
            [PSCustomObject]@{ SamAccountName = "svc_web1"; ServicePrincipalNames = "HTTP/web01" }
        )
        $computers = @(
            [PSCustomObject]@{ SamAccountName = "WEB01$"; ServicePrincipalNames = "HOST/WEB01" }
        )
        $result = @(Test-DuplicateSPNs -Users $users -Computers $computers)
        $result.Count | Should Be 0
    }
}
