# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224941
Rule ID:    SV-224941r852331_rule
STIG ID:    WN16-CC-000340
Legacy:     V-73561; SV-88225
Rule Title: Explorer Data Execution Prevention must be enabled.
Discussion:
Data Execution Prevention provides additional protection by performing checks on memory to help prevent malicious code from running. This setting will prevent Data Execution Prevention from being turned off for File Explorer.


Check Content:
The default behavior is for Data Execution Prevention to be turned on for File Explorer.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\

Value Name: NoDataExecutionPrevention

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
    Name = "NoDataExecutionPrevention"
    ExpectedValue = 0
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params