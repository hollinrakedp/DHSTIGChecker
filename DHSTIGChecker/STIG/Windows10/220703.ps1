<#
Rule Title: Windows 10 systems must use a BitLocker PIN for pre-boot authentication.
Severity: medium
Vuln ID: V-220703
STIG ID: WN10-00-000031

Discussion:
If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing encrypted drives.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

For WVD implementations with no data at rest, this is NA.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\FVE\

Value Name: UseAdvancedStartup
Type: REG_DWORD
Value: 0x00000001 (1)

If one of the following registry values does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\FVE\

Value Name: UseTPMPIN
Type: REG_DWORD
Value: 0x00000001 (1)

Value Name: UseTPMKeyPIN
Type: REG_DWORD
Value: 0x00000001 (1)

When BitLocker network unlock is used:

Value Name: UseTPMPIN
Type: REG_DWORD
Value: 0x00000002 (2)

Value Name: UseTPMKeyPIN
Type: REG_DWORD
Value: 0x00000002 (2)

BitLocker network unlock may be used in conjunction with a BitLocker PIN. See the article below regarding information about network unlock.

https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-enable-network-unlock

#>

if ($Script:isVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "This check does not apply: Reason - Non-Persistent VDI"
        return "Not Applicable"
    }
}

$Local:Results = @()

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
    Name = "UseAdvancedStartup"
    ExpectedValue = 1
}

$Local:Results += Compare-RegKeyValue @Params

$ValidValues = 1, 2
$Check = @()
foreach ($Value in $ValidValues) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
        Name          = "UseTPMPIN"
        ExpectedValue = $Value
    }
    
    $Check += Compare-RegKeyValue @Params
}

$Local:Results += switch ($Check -contains $true) {
    True { $true }
    False { $false }
}

$ValidValues = 1, 2
$Check = @()
foreach ($Value in $ValidValues) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
        Name          = "UseTPMKeyPIN"
        ExpectedValue = $Value
    }
    
    $Check += Compare-RegKeyValue @Params
}

$Local:Results += switch ($Check -contains $true) {
    True { $true }
    False { $false }
}

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}