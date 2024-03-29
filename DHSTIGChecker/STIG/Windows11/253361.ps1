# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253361
Rule ID:    SV-253361r829167_rule
STIG ID:    WN11-CC-000044
Legacy:     
Rule Title: Internet connection sharing must be disabled.
Discussion:
Internet connection sharing makes it possible for an existing internet connection, such as through wireless, to be shared and used by other systems essentially creating a mobile hotspot. This exposes the system sharing the connection to others with potentially malicious purpose.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Network Connections\

Value Name: NC_ShowSharedAccessUI

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\"
    Name = "NC_ShowSharedAccessUI"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params