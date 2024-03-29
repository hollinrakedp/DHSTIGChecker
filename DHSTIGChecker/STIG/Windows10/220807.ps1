# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220807
Rule ID:    SV-220807r569187_rule
STIG ID:    WN10-CC-000060
Legacy:     V-63585; SV-78075
Rule Title: Connections to non-domain networks when connected to a domain authenticated network must be blocked.
Discussion:
Multiple network connections can provide additional attack vectors to a system and should be limited.  When connected to a domain, communication must go through the domain connection.


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