<#
Rule Title: Non system-created file shares on a system must limit access to groups that require it.
Severity: medium
Vuln ID: V-220710
STIG ID: WN10-00-000060

Discussion:
Shares which provide network access, should not typically exist on a workstation except for system-created administrative shares, and could potentially expose sensitive information.  If a share is necessary, share permissions, as well as NTFS permissions, must be reconfigured to give the minimum access to those accounts that require it.


Check Content:
Non system-created shares should not typically exist on workstations.

If only system-created shares exist on the system this is NA.

Run "Computer Management".
Navigate to System Tools >> Shared Folders >> Shares.

If the only shares listed are "ADMIN$", "C$" and "IPC$", this is NA.
(Selecting Properties for system-created shares will display a message that it has been shared for administrative purposes.)

Right click any non-system-created shares.
Select "Properties".
Select the "Share Permissions" tab.

Verify the necessity of any shares found.
If the file shares have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the "Security" tab.

If the NTFS permissions have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.

#>
$IgnoreDescription = @('Remote Admin','Default share','Remote IPC')
$ReviewShares = Get-SmbShare | Where-Object {$_.Description -notin $IgnoreDescription}  

if ($ReviewShares.count -eq 0) {
    $true
}
else {
    "Not Reviewed"
}