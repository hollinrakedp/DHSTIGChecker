<#
Rule Title: Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.
Severity: medium
Vuln ID: V-205826
STIG ID: WN19-SO-000170

Discussion:
The server message block (SMB) protocol provides the basis for many network operations. If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
    Name          = "EnableSecuritySignature"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params