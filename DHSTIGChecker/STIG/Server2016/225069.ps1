# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225069
Rule ID:    SV-225069r569186_rule
STIG ID:    WN16-UC-000030
Legacy:     V-73727; SV-88391
Rule Title: Zone information must be preserved when saving attachments.
Discussion:
Attachments from outside sources may contain malicious code. Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.


Check Content:
The default behavior is for Windows to mark file attachments with their zone information.

If the registry Value Name below does not exist, this is not a finding.

If it exists and is configured with a value of "2", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: SaveZoneInformation

Value Type: REG_DWORD
Value: 0x00000002 (2) (or if the Value Name does not exist)
#>

$Params = @{
    Path          = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
    Name          = "SaveZoneInformation"
    ExpectedValue = 2
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params