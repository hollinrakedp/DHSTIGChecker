# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224948
Rule ID:    SV-224948r877394_rule
STIG ID:    WN16-CC-000410
Legacy:     V-73575; SV-88239
Rule Title: Remote Desktop Services must be configured with the client connection encryption set to High Level.
Discussion:
Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 0x00000003 (3)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "MinEncryptionLevel"
    ExpectedValue = 3
}

Compare-RegKeyValue @Params