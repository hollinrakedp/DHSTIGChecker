<#
Rule Title: Windows Server 2019 passwords for the built-in Administrator account must be changed at least every 60 days.
Severity: medium
Vuln ID: V-205657
STIG ID: WN19-00-000020

Discussion:
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password not may be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

It is highly recommended to use Microsoft's Local Administrator Password Solution (LAPS). Domain-joined systems can configure this to occur more frequently. LAPS will change the password every "30" days by default. The AO still has the overall authority to use another equivalent capability to accomplish the check.


Check Content:
Review the password last set date for the built-in Administrator account.

Domain controllers:

Open "PowerShell".

Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

Member servers and standalone systems:

Open "Command Prompt".

Enter 'Net User [account name] | Find /i "Password Last Set"', where [account name] is the name of the built-in administrator account.

(The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

#>

# Checking all accounts not just members of Administrators

$AcctStalePW = Get-LocalUser | Where-Object { ($_.Enabled -eq $true) -and ($_.PasswordLastSet -le $(Get-Date).AddDays(-60))}

if ($AcctStalePW) {
    Write-Verbose "This check failed: Reason - Found Account(s) with stale password: $($AcctStalePW.Name -join ', ')"
    $false
}
else {
    $true
}