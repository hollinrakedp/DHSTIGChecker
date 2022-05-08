<#
Rule Title: Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
Severity: low
Vuln ID: V-205691
STIG ID: WN19-CC-000200

Discussion:
Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.

This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\AppCompat\

Value Name: DisableInventory

Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
    Name          = "DisableInventory"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params