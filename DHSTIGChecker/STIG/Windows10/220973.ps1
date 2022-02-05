<#
Rule Title: The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts.
Severity: medium
Vuln ID: V-220973
STIG ID: WN10-UR-000095

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could potentially allow unauthorized users to impersonate other users.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.

#>

if ($null -eq $Script:CurrentSecPolicy.SeEnableDelegationPrivilege) {
    $true
}
else {
    $false
}