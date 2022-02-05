<#
Rule Title: Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge.
Severity: medium
Vuln ID: V-220840
STIG ID: WN10-CC-000230

Discussion:
The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender SmartScreen filter they could still access malicious websites.


Check Content:
This is applicable to unclassified systems, for other systems this is NA.

Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\

Value Name: PreventOverride

Type: REG_DWORD
Value: 0x00000001 (1)

#>

if ($Script:IsClassified) {
    Write-Verbose "This check does not apply: Reason - Not an Unclassified System"
    return "Not Applicable"
}
else {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
        Name          = "PreventOverride"
        ExpectedValue = 1
    }

    Compare-RegKeyValue @Params
}