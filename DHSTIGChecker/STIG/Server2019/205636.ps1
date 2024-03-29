# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205636
Rule ID:    SV-205636r877398_rule
STIG ID:    WN19-CC-000370
Legacy:     V-92971; SV-103059
Rule Title: Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.
Discussion:
Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.

Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000250-GPOS-00093


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name          = "fEncryptRPCTraffic"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params