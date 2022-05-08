<#
Rule Title: Windows Server 2019 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.
Severity: medium
Vuln ID: V-205828
STIG ID: WN19-SO-000200

Discussion:
The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
    Name          = "EnableSecuritySignature"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params