# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-205871
Rule ID:    SV-205871r569188_rule
STIG ID:    WN19-CC-000320
Legacy:     V-93261; SV-103349
Rule Title: Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled.
Discussion:
Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.


Check Content:
The default behavior is for File Explorer heap termination on corruption to be enabled.

If the registry Value Name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

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