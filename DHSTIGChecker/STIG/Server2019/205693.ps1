# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205693
Rule ID:    SV-205693r569188_rule
STIG ID:    WN19-CC-000400
Legacy:     V-93413; SV-103499
Rule Title: Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP.
Discussion:
Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.


Check Content:
The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: AllowBasicAuthInClear

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
    Name          = "AllowBasicAuthInClear"
    ExpectedValue = 0
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params