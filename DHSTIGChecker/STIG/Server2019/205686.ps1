# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205686
Rule ID:    SV-205686r569188_rule
STIG ID:    WN19-CC-000010
Legacy:     V-93399; SV-103485
Rule Title: Windows Server 2019 must prevent the display of slide shows on the lock screen.
Discussion:
Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user.


Check Content:
Verify the registry value below. 

If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 0x00000001 (1)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
    Name = "NoLockScreenSlideshow"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params