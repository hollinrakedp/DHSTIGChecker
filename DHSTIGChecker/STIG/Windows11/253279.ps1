# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253279
Rule ID:    SV-253279r828921_rule
STIG ID:    WN11-00-000120
Legacy:     
Rule Title: The TFTP Client must not be installed on the system.
Discussion:
The "TFTP Client" is not installed by default. Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
Verify TFTP Client has not been installed.

Navigate to the Windows\System32 directory.

If the "TFTP" application exists, this is a finding.
#>

$Local:Feature = Get-WindowsOptionalFeature -Online -FeatureName "TFTP"

if ($Local:Feature.State -contains 'Enabled') {
    $false
}
else {
    $true
}