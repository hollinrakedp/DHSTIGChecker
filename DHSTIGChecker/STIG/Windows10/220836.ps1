<#
Rule Title: The Windows Defender SmartScreen for Explorer must be enabled.
Severity: medium
Vuln ID: V-220836
STIG ID: WN10-CC-000210

Discussion:
Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling Windows Defender SmartScreen will warn or prevent users from running potentially malicious programs.


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

v1607 LTSB:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)

v1507 LTSB:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000002 (2)

#>

# Not checking for LTSB

if ($Script:IsClassified) {
    Write-Verbose "This check does not apply: Reason - Not an Unclassified System"
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