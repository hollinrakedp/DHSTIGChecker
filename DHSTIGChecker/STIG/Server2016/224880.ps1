# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224880
Rule ID:    SV-224880r569186_rule
STIG ID:    WN16-AU-000060
Legacy:     V-73411; SV-88063
Rule Title: Event Viewer must be protected from unauthorized modification and deletion.
Discussion:
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification or deletion of audit tools.

Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000258-GPOS-00099


Check Content:
Navigate to "%SystemRoot%\System32".

View the permissions on "Eventvwr.exe".

If any groups or accounts other than TrustedInstaller have "Full control" or "Modify" permissions, this is a finding.

The default permissions below satisfy this requirement:

TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES - Read & Execute
#>

# INCOMPLETE
return 'Not Reviewed'
