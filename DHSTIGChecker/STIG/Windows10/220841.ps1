# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220841
Rule ID:    SV-220841r569187_rule
STIG ID:    WN10-CC-000235
Legacy:     V-63701; SV-78191
Rule Title: Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge.
Discussion:
The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender SmartScreen filter they could still download potentially malicious files.


Check Content:
This is applicable to unclassified systems, for other systems this is NA.

Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\

Value Name: PreventOverrideAppRepUnknown

Type: REG_DWORD
Value: 0x00000001 (1)
#>

# No check for LTSB/LTSC
if ($Script:IsClassified) {
    Write-Verbose "Reason: Not an Unclassified System"
    return "Not Applicable"
}
else {
    $Params = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
        Name = "PreventOverrideAppRepUnknown"
        ExpectedValue = 1
    }
    
    Compare-RegKeyValue @Params
}