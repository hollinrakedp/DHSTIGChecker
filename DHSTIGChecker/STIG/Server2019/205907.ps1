<#
Rule Title: Windows Server 2019 must be running Credential Guard on domain-joined member servers.
Severity: high
Vuln ID: V-205907
STIG ID: WN19-MS-000140

Discussion:
Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.


Check Content:
For domain controllers and standalone systems, this is NA.

Open "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "Device Guard Security Services Running" does not list "Credential Guard", this is a finding.

The policy settings referenced in the Fix section will configure the following registry value. However, due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock)

A Microsoft article on Credential Guard system requirement can be found at the following link:

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements

#>
if (!($Script:IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Standalone system"
    "Not Applicable"
}
elseif ($Script:IsDomainController) {
    Write-Verbose "This check does not apply: Reason - Domain Controller"
    "Not Applicable"
}
else {
    "Not Reviewed"
}
