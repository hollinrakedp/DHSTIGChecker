# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220827
Rule ID:    SV-220827r851989_rule
STIG ID:    WN10-CC-000180
Legacy:     V-63667; SV-78157
Rule Title: Autoplay must be turned off for non-volume devices.
Discussion:
Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs or music on audio media may start.  This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\

Value Name: NoAutoplayfornonVolume

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
    Name = "NoAutoplayfornonVolume"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params