<#
Rule Title: The password manager function in the Edge browser must be disabled.
Severity: medium
Vuln ID: V-220843
STIG ID: WN10-CC-000245

Discussion:
Passwords save locally for re-use when browsing may be subject to compromise.  Disabling the Edge password manager will prevent this for the browser.


Check Content:
Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\

Value Name: FormSuggest Passwords

Type: REG_SZ
Value: no

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"
    Name = "FormSuggest Passwords"
    ExpectedValue = "no"
}

Compare-RegKeyValue @Params