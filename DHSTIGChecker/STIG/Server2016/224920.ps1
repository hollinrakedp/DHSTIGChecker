# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224920
Rule ID:    SV-224920r569186_rule
STIG ID:    WN16-CC-000080
Legacy:     V-73507; SV-88159
Rule Title: Insecure logons to an SMB server must be disabled.
Discussion:
Insecure guest logons allow unauthenticated access to shared folders. Shared resources on a system must require authentication to establish proper access.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\

Value Name: AllowInsecureGuestAuth

Type: REG_DWORD
Value: 0x00000000 (0)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
    Name = "AllowInsecureGuestAuth"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params