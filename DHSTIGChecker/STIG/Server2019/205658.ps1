# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205658
Rule ID:    SV-205658r857297_rule
STIG ID:    WN19-00-000210
Legacy:     V-93475; SV-103561
Rule Title: Windows Server 2019 passwords must be configured to expire.
Discussion:
Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.


Check Content:
Review the password never expires status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled".

Exclude application accounts, disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

If any enabled user accounts are returned with a "PasswordNeverExpires" status of "True", this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'.

Exclude application accounts and disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.
#>

$Accounts = Get-CimInstance -Query 'SELECT name FROM Win32_UserAccount WHERE LocalAccount=TRUE AND Disabled=FALSE AND PasswordExpires=FALSE' -Verbose:$false

if ($null -eq $Accounts) {
    $true
}
else {
    $false
}