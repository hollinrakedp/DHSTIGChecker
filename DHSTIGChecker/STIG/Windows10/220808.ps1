<#
Rule Title: Wi-Fi Sense must be disabled.
Severity: medium
Vuln ID: V-220808
STIG ID: WN10-CC-000065

Discussion:
Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared.  It also allows the sharing of the system's known networks to contacts.  Automatically connecting to hotspots and shared networks can expose a system to unsecured or potentially malicious systems.


Check Content:
This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\

Value Name: AutoConnectAllowedOEM

Type: REG_DWORD
Value: 0x00000000 (0)

#>
if (!($Script:ComputerInfo.WindowsVersion -lt 1803)) {
    return 'Not Applicable'
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\"
    Name = "AutoConnectAllowedOEM"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params