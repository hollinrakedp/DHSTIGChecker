# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253462
Rule ID:    SV-253462r829470_rule
STIG ID:    WN11-SO-000205
Legacy:     
Rule Title: The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
Discussion:
The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to stand-alone computers that are running later versions.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

Value Name: LmCompatibilityLevel

Value Type: REG_DWORD
Value: 5
#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
    Name          = "LmCompatibilityLevel"
    ExpectedValue = 5
}

Compare-RegKeyValue @Params