# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220852
Rule ID:    SV-220852r877398_rule
STIG ID:    WN10-CC-000290
Legacy:     V-63741; SV-78231
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