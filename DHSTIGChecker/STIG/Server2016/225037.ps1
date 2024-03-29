# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-225037
Rule ID:    SV-225037r569186_rule
STIG ID:    WN16-SO-000160
Legacy:     V-73649; SV-88313
Rule Title: The Windows dialog box title for the legal banner must be configured with the appropriate text.
Discussion:
Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.

Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000228-GPOS-00088


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeCaption

Value Type: REG_SZ
Value: See message title options below

"DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or an organization-defined equivalent. 

If an organization-defined title is used, it can in no case contravene or modify the language of the banner text required in WN16-SO-000150.

Automated tools may only search for the titles defined above. If an organization-defined title is used, a manual review will be required.
#>

$Local:Results = @()
$ValidValues = "DoD Notice and Consent Banner", "US Department of Defense Warning Statement"

foreach ($Value in $ValidValues) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
        Name          = "LegalNoticeCaption"
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