<#
Rule Title: Credential Guard must be running on Windows 10 domain-joined systems.
Severity: high
Vuln ID: V-220812
STIG ID: WN10-CC-000075

Discussion:
Credential Guard uses virtualization based security to protect information that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.


Check Content:
Confirm Credential Guard is running on domain-joined systems.

For those devices that support Credential Guard, this feature must be enabled. Organizations need to take the appropriate action to acquire and implement compatible hardware with Credential Guard enabled.

Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "PowerShell" with elevated privileges (run as administrator).
Enter the following:
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".
Under "System Summary", verify the following:
If "Device Guard Security Services Running" does not list "Credential Guard", this is finding.

The policy settings referenced in the Fix section will configure the following registry value. However, due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock)



#>

if ($Script:isVDI) {
    if ($Script:VDIPersist) {
        return "Not Applicable"
    }
}

$Script:DeviceGuard.SecurityServicesRunning -contains 1