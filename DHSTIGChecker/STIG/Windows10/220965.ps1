<#
Rule Title: The Create permanent shared objects user right must not be assigned to any groups or accounts.
Severity: medium
Vuln ID: V-220965
STIG ID: WN10-UR-000055

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Create permanent shared objects" user right, this is a finding.

#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeCreatePermanentPrivilege -split ',').trimstart('*')

if ($null -eq $GrantedPrivilege) {
    $true
}
else {
    $false
}