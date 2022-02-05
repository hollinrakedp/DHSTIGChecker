<#
Rule Title: The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
Severity: low
Vuln ID: V-220826
STIG ID: WN10-CC-000175

Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\AppCompat\

Value Name: DisableInventory

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path = "\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
    Name = "DisableInventory"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params