# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253366
Rule ID:    SV-253366r829182_rule
STIG ID:    WN11-CC-000065
Legacy:     
Rule Title: Wi-Fi Sense must be disabled.
Discussion:
Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared. It also allows the sharing of the system's known networks to contacts. Automatically connecting to hotspots and shared networks can expose a system to unsecured or potentially malicious systems.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\

Value Name: AutoConnectAllowedOEM

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\"
    Name = "AutoConnectAllowedOEM"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params