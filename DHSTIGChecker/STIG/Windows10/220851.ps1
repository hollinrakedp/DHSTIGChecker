# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220851
Rule ID:    SV-220851r877394_rule
STIG ID:    WN10-CC-000285
Legacy:     V-63737; SV-78227
Rule Title: The Remote Desktop Session Host must require secure RPC communications.
Discussion:
Allowing unsecure RPC communication exposes the system to man in the middle attacks and data disclosure attacks. A man in the middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fEncryptRPCTraffic

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "fEncryptRPCTraffic"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params