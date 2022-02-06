<#
Rule Title: The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.
Severity: medium
Vuln ID: V-220730
STIG ID: WN10-00-000165

Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only support SMBv1.


Check Content:
Different methods are available to disable SMBv1 on Windows 10, if V-220729 is configured, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)

#>

$220729 = $Script:VulnResults | Where-Object {$_.VulnID -eq "220729"}
if ($220729.Result -eq "Not a Finding") {
    Write-Verbose "This check does not apply: Reason - V-220729 is configured"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
    Name = "SMB1"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params