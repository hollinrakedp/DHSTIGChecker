# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253406
Rule ID:    SV-253406r877398_rule
STIG ID:    WN11-CC-000290
Legacy:     
Rule Title: Remote Desktop Services must be configured with the client connection encryption set to the required level.
Discussion:
Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MinEncryptionLevel

Value Type: REG_DWORD
Value: 3
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "MinEncryptionLevel"
    ExpectedValue = 3
}

Compare-RegKeyValue @Params