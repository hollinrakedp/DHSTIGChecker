<#
Rule Title: The Lock pages in memory user right must not be assigned to any groups or accounts.
Severity: medium
Vuln ID: V-220977
STIG ID: WN10-UR-000125

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause performance issues or a DoS.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Lock pages in memory" user right, this is a finding.

#>

if ($null -eq $Script:CurrentSecPolicy.SeLockMemoryPrivilege) {
    $true
}
else {
    $false
}