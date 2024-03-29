# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253372
Rule ID:    SV-253372r829200_rule
STIG ID:    WN11-CC-000085
Legacy:     
Rule Title: Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.
Discussion:
The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy is to enforce "Good, unknown and bad but critical" (preventing "bad"). By being launched first by the kernel, ELAM ( Early Launch Antimalware) is ensured to be launched before any third-party software, and is therefore able to detect malware in the boot process and prevent it from initializing.


Check Content:
The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy is to enforce "Good, unknown and bad but critical" (preventing "bad").

If the registry value name below does not exist, this is a finding.

If it exists and is configured with a value of "7", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Policies\EarlyLaunch\

Value Name: DriverLoadPolicy

Value Type: REG_DWORD
Value: 1, 3, or 8 

Possible values for this setting are:
8 - Good only
1 - Good and unknown
3 - Good, unknown and bad but critical
7 - All (which includes "Bad" and would be a finding)
#>

$Local:Results = @()
$Local:ValidValues = 1, 3, 8

foreach ($Value in $Local:ValidValues) {
    $Params = @{
        Path          = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
        Name          = "DriverLoadPolicy"
        ExpectedValue = $Value
    }
    
    $Local:Results += Compare-RegKeyValue @Params
}

if ($Local:Results -contains $true) {
    $true
}
else {
    $false
}