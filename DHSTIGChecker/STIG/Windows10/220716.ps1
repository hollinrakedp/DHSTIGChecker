# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220716
Rule ID:    SV-220716r569187_rule
STIG ID:    WN10-00-000090
Legacy:     V-63371; SV-77861
Rule Title: Accounts must be configured to require password expiration.
Discussion:
Passwords that do not expire increase exposure with a greater probability of being discovered or cracked.


Check Content:
Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.
Double click each active account.

If "Password never expires" is selected for any account, this is a finding.
#>

$Accounts = Get-CimInstance -Query 'SELECT name FROM Win32_UserAccount WHERE LocalAccount=TRUE AND Disabled=FALSE AND PasswordExpires=FALSE' -Verbose:$false

if ($null -eq $Accounts) {
    $true
}
else {
    $false
}