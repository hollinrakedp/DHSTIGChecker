# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253395
Rule ID:    SV-253395r829269_rule
STIG ID:    WN11-CC-000210
Legacy:     
Rule Title: The Microsoft Defender SmartScreen for Explorer must be enabled.
Discussion:
Microsoft Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling Microsoft Defender SmartScreen will warn or prevent users from running potentially malicious programs.


Check Content:
This is applicable to unclassified systems, for other systems this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)

And

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: ShellSmartScreenLevel

Value Type: REG_SZ
Value: Block
#>

if ($Script:IsClassified) {
    Write-Verbose "Reason: Not an Unclassified System"
    return "Not Applicable"
}

$Local:Results = @()

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name          = "EnableSmartScreen"
    ExpectedValue = 1
}
    
$Local:Results += Compare-RegKeyValue @Params

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name          = "ShellSmartScreenLevel"
    ExpectedValue = "Block"
}
    
$Local:Results += Compare-RegKeyValue @Params

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}