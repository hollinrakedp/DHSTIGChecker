# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224887
Rule ID:    SV-224887r569186_rule
STIG ID:    WN16-AU-000160
Legacy:     V-73431; SV-88083
Rule Title: Windows Server 2016 must be configured to audit Detailed Tracking - Plug and Play Events successes.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Plug and Play activity records events related to the successful connection of external devices.


Check Content:
Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN16-SO-000050) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following.

If the system does not audit the following, this is a finding.

Detailed Tracking >> Plug and Play Events - Success
#>

$Local:Category = "Plug and Play Events"
$Local:Setting = "Success"

$Local:AuditSetting = $Script:AuditPolicy | Where-Object {$_.Subcategory -contains "$Local:Category"}

if ($Local:AuditSetting.'Inclusion Setting' -match $Local:Setting) {
    $true
}
else {
    $false
}