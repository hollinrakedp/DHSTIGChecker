<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 2 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-253349
Rule ID:    SV-253349r829131_rule
STIG ID:    WN11-AU-000580
Legacy:     
Rule Title: Windows 11 must be configured to audit MPSSVC Rule-Level Policy Change Failures.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit MPSSVC Rule-Level Policy Change determines whether the operating system generates audit events when changes are made to policy rules for the Microsoft Protection Service (MPSSVC.exe).


Check Content:
Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Policy Change >> MPSSVC Rule-Level Policy Change - Failure
#>

$Local:Category = "MPSSVC Rule-Level Policy Change"
$Local:Setting = "Failure"

$Local:AuditSetting = $Script:AuditPolicy | Where-Object {$_.Subcategory -contains "$Local:Category"}

if ($Local:AuditSetting.'Inclusion Setting' -match $Local:Setting) {
    $true
}
else {
    $false
}