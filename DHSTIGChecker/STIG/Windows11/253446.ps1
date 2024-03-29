# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253446
Rule ID:    SV-253446r829422_rule
STIG ID:    WN11-SO-000080
Legacy:     
Rule Title: The Windows message title for the legal notice must be configured.
Discussion:
Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeCaption

Value Type: REG_SZ
Value: See message title above

"DoD Notice and Consent Banner", "US Department of Defense Warning Statement" or a site-defined equivalent, this is a finding.

If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in WN11-SO-000075.
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