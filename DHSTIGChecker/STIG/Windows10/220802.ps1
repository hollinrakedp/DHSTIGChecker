# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220802
Rule ID:    SV-220802r569187_rule
STIG ID:    WN10-CC-000040
Legacy:     V-63569; SV-78059
Rule Title: Insecure logons to an SMB server must be disabled.
Discussion:
Insecure guest logons allow unauthenticated access to shared folders.  Shared resources on a system must require authentication to establish proper access.


Check Content:
Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\

Value Name: AllowInsecureGuestAuth

Type: REG_DWORD
Value: 0x00000000 (0)
#>

# No check for LTSB/LTSC
$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
    Name = "AllowInsecureGuestAuth"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params