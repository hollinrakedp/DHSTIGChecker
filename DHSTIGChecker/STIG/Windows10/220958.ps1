<#
Rule Title: The Act as part of the operating system user right must not be assigned to any groups or accounts.
Severity: high
Vuln ID: V-220958
STIG ID: WN10-UR-000015

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts (to include administrators), are granted the "Act as part of the operating system" user right, this is a finding.

#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeTcbPrivilege -split ',').trimstart('*')

if ($null -eq $GrantedPrivilege) {
    $true
}
else {
    $false
}