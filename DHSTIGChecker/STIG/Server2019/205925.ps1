# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205925
Rule ID:    SV-205925r877377_rule
STIG ID:    WN19-CC-000450
Legacy:     V-93269; SV-103357
Rule Title: Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart.
Discussion:
Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.


Check Content:
Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name = "DisableAutomaticRestartSignOn"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params