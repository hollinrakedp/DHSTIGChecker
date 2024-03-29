# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253323
Rule ID:    SV-253323r829053_rule
STIG ID:    WN11-AU-000085
Legacy:     
Rule Title: The system must be configured to audit Object Access - Removable Storage failures.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing object access for removable media records events related to access attempts on file system objects on removable storage devices.


Check Content:
Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Object Access >> Removable Storage - Failure

Some virtual machines may generate excessive audit events for access to the virtual hard disk itself when this setting is enabled. This may be set to Not Configured in such cases and would not be a finding. This must be documented with the ISSO to include mitigations such as monitoring or restricting any actual removable storage connected to the VM.
#>

$Local:Category = "Removable Storage"
$Local:Setting = "Failure"

$Local:AuditSetting = $Script:AuditPolicy | Where-Object {$_.Subcategory -contains "$Local:Category"}

if ($Local:AuditSetting.'Inclusion Setting' -match $Local:Setting) {
    $true
}
else {
    $false
}