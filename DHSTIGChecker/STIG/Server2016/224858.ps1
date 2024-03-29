# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224858
Rule ID:    SV-224858r569186_rule
STIG ID:    WN16-00-000412
Legacy:     V-78125; SV-92831
Rule Title: The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.
Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.


Check Content:
Different methods are available to disable SMBv1 on Windows 2016, if V-73299 is configured, this is NA.

If the following registry value is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\mrxsmb10\

Value Name: Start

Type: REG_DWORD
Value: 0x00000004 (4)
#>

$224856 = $Script:VulnResults | Where-Object {$_.VulnID -eq "224856"}
if ($224856.Result -eq "Not a Finding") {
    Write-Verbose "Reason: V-224856 is configured"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\"
    Name = "Start"
    ExpectedValue = 4
}

Compare-RegKeyValue @Params