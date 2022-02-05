<#
Rule Title: Printing over HTTP must be prevented.
Severity: medium
Vuln ID: V-220817
STIG ID: WN10-CC-000110

Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\

Value Name: DisableHTTPPrinting

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
    Name = "DisableHTTPPrinting"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params