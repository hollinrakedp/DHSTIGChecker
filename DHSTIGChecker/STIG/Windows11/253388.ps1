# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253388
Rule ID:    SV-253388r829248_rule
STIG ID:    WN11-CC-000190
Legacy:     
Rule Title: Autoplay must be disabled for all drives.
Discussion:
Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon as media is inserted in the drive. As a result, the setup file of programs or music on audio media may start. By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. If this policy is enabled, autoplay can be disabled on all drives.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\

Value Name: NoDriveTypeAutoRun

Value Type: REG_DWORD
Value: 0x000000ff (255)

Note: If the value for NoDriveTypeAutorun is entered manually, it must be entered as "ff" when Hexadecimal is selected, or "255" with Decimal selected. Using the policy value specified in the Fix section will enter it correctly.
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\"
    Name = "NoDriveTypeAutoRun"
    ExpectedValue = 255
}

Compare-RegKeyValue @Params