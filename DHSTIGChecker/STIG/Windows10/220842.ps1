<#
Rule Title: Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge.
Severity: medium
Vuln ID: V-220842
STIG ID: WN10-CC-000238

Discussion:
Web security certificates provide an indication whether a site is legitimate. This policy setting prevents the user from ignoring Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificate errors that interrupt browsing.


Check Content:
This setting is applicable starting with v1809 of Windows 10; it is NA for prior versions.

Windows 10 LTSC\B versions do not include Microsoft Edge; this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\

Value Name: PreventCertErrorOverrides

Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\"
    Name = "PreventCertErrorOverrides"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params