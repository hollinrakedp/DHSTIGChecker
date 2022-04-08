<#
Rule Title: Windows Server 2019 Event Viewer must be protected from unauthorized modification and deletion.
Severity: medium
Vuln ID: V-205731
STIG ID: WN19-AU-000060

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
return 'Not Reviewed'
