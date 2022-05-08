<#
Rule Title: Windows Server 2019 Windows Defender SmartScreen must be enabled.
Severity: medium
Vuln ID: V-205692
STIG ID: WN19-CC-000300

Discussion:
Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen can block potentially malicious programs or warn users.


Check Content:
This is applicable to unclassified systems; for other systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)

#>

if ($Script:IsClassified) {
    Write-Verbose "This check does not apply: Reason - Not an Unclassified System"
    return "Not Applicable"
}

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
    Name          = "EnableSmartScreen"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params