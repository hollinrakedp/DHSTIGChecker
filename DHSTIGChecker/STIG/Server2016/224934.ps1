# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224934
Rule ID:    SV-224934r852327_rule
STIG ID:    WN16-CC-000270
Legacy:     V-73549; SV-88213
Rule Title: AutoPlay must be disabled for all drives.
Discussion:
Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. By default, AutoPlay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. Enabling this policy disables AutoPlay on all drives.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\

Value Name: NoDriveTypeAutoRun

Type: REG_DWORD
Value: 0x000000ff (255)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\"
    Name = "NoDriveTypeAutoRun"
    ExpectedValue = 255
}

Compare-RegKeyValue @Params