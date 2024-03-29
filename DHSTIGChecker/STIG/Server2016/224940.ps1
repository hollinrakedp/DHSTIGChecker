# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224940
Rule ID:    SV-224940r569186_rule
STIG ID:    WN16-CC-000330
Legacy:     V-73559; SV-88223
Rule Title: Windows Server 2016 Windows SmartScreen must be enabled.
Discussion:
Windows SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen will warn users of potentially malicious programs.


Check Content:
This is applicable to unclassified systems; for other systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

if ($Script:IsClassified) {
    'Not Applicable'
}
else {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
        Name          = "EnableSmartScreen"
        ExpectedValue = 1
    }
    
    Compare-RegKeyValue @Params
}