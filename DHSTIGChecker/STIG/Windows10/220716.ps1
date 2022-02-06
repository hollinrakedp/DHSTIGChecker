<#
Rule Title: Accounts must be configured to require password expiration.
Severity: medium
Vuln ID: V-220716
STIG ID: WN10-00-000090

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