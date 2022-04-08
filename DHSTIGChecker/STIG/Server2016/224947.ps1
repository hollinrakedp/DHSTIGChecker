<#
Rule Title: The Remote Desktop Session Host must require secure Remote Procedure Call (RPC) communications.
Severity: medium
Vuln ID: V-224947
STIG ID: WN16-CC-000400

Discussion:
Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 0x00000001 (1)

#>
return 'Not Reviewed'
