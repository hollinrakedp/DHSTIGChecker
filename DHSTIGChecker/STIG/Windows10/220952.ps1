<#
Rule Title: Passwords for enabled local Administrator accounts must be changed at least every 60 days.
Severity: medium
Vuln ID: V-220952
STIG ID: WN10-SO-000280

Discussion:
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. A local Administrator account is not generally used and its password not may be changed as frequently as necessary. Changing the password for enabled Administrator accounts on a regular basis will limit its exposure.

It is highly recommended to use Microsoft's Local Administrator Password Solution (LAPS). Domain-joined systems can configure this to occur more frequently. LAPS will change the password every "30" days by default. The AO still has the overall authority to use another equivalent capability to accomplish the check.


Check Content:
Review the password last set date for the enabled local Administrator account.

On the local domain joined workstation:

Open "PowerShell".

Enter "Get-LocalUser �Name * | Select-Object *�

If the "PasswordLastSet" date is greater than "60" days old for the local Administrator account for administering the computer/domain, this is a finding.

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