# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205721
Rule ID:    SV-205721r569188_rule
STIG ID:    WN19-00-000230
Legacy:     V-93531; SV-103617
Rule Title: Windows Server 2019 non-system-created file shares must limit access to groups that require it.
Discussion:
Shares on a system provide network access. To prevent exposing sensitive information, where shares are necessary, permissions must be reconfigured to give the minimum access to accounts that require it.


Check Content:
If only system-created shares such as "ADMIN$", "C$", and "IPC$" exist on the system, this is NA. (System-created shares will display a message that it has been shared for administrative purposes when "Properties" is selected.)

Run "Computer Management".

Navigate to System Tools >> Shared Folders >> Shares.

Right-click any non-system-created shares.

Select "Properties".

Select the "Share Permissions" tab.

If the file shares have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the "Security" tab.

If the permissions have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
