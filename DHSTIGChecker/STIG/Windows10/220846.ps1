<#
Rule Title: The use of a hardware security device with Windows Hello for Business must be enabled.
Severity: medium
Vuln ID: V-220846
STIG ID: WN10-CC-000255

Discussion:
The use of a Trusted Platform Module (TPM) to store keys for Windows Hello for Business provides additional security.  Keys stored in the TPM may only be used on that system while keys stored using software are more susceptible to compromise and could be used on other systems.


Check Content:
Virtual desktop implementations currently may not support the use of TPMs. For virtual desktop implementations where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\PassportForWork\

Value Name: RequireSecurityDevice

Type: REG_DWORD
Value: 1

#>

if ($Script:isVDI) {
    if ($Script:VDIPersist) {
        return "Not Applicable"
    }
}

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\"
    Name          = "RequireSecurityDevice"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params