# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253365
Rule ID:    SV-253365r829179_rule
STIG ID:    WN11-CC-000060
Legacy:     
Rule Title: Connections to non-domain networks when connected to a domain authenticated network must be blocked.
Discussion:
Multiple network connections can provide additional attack vectors to a system and must be limited. When connected to a domain, communication must go through the domain connection.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\

Value Name: fBlockNonDomain

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\"
    Name = "fBlockNonDomain"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params