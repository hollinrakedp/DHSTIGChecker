# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220718
Rule ID:    SV-220718r569187_rule
STIG ID:    WN10-00-000100
Legacy:     V-63377; SV-77867
Rule Title: Internet Information System (IIS) or its subcomponents must not be installed on a workstation.
Discussion:
Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted.  Websites must only be hosted on servers that have been designed for that purpose and can be adequately secured.


Check Content:
IIS is not installed by default.  Verify it has not been installed on the system.

Run "Programs and Features".
Select "Turn Windows features on or off".

If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are selected, this is a finding.

If an application requires IIS or a subset to be installed to function, this needs be documented with the ISSO.  In addition, any applicable requirements from the IIS STIG must be addressed.
#>

$Local:Feature = Get-WindowsOptionalFeature -Online -FeatureName IIS*

if ($Local:Feature.State -contains 'Enabled') {
    $false
}
else {
    $true
}