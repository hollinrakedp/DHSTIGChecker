# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253397
Rule ID:    SV-253397r829275_rule
STIG ID:    WN11-CC-000220
Legacy:     
Rule Title: File Explorer heap termination on corruption must be disabled.
Discussion:
Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.


Check Content:
The default behavior is for File Explorer heap termination on corruption to be enabled.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\

Value Name: NoHeapTerminationOnCorruption

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
    Name          = "NoHeapTerminationOnCorruption"
    ExpectedValue = 0
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params