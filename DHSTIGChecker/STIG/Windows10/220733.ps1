# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220733
Rule ID:    SV-220733r569187_rule
STIG ID:    WN10-00-000190
Legacy:     V-76505; SV-91201
Rule Title: Orphaned security identifiers (SIDs) must be removed from user rights on Windows 10.
Discussion:
Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including deletion of the accounts or groups.  If the account or group objects are reanimated, there is a potential they may still have rights no longer intended.  Valid domain accounts or groups may also show up as unresolved SIDs if a connection to the domain cannot be established for some reason.


Check Content:
Review the effective User Rights setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

Review each User Right listed for any unresolved SIDs to determine whether they are valid, such as due to being temporarily disconnected from the domain. (Unresolved SIDs have the format of "*S-1-…".)

If any unresolved SIDs exist and are not for currently valid accounts or groups, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
