# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253369
Rule ID:    SV-253369r829191_rule
STIG ID:    WN11-CC-000070
Legacy:     
Rule Title: Virtualization-based Security must be enabled on Windows 11 with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.
Discussion:
Virtualization-based Security (VBS) provides the platform for the additional security features, Credential Guard and virtualization-based protection of code integrity. Secure Boot is the minimum security level with DMA protection providing additional memory protection. DMA Protection requires a CPU that supports input/output memory management unit (IOMMU).


Check Content:
Confirm virtualization-based Security is enabled and running with Secure Boot or Secure Boot and DMA Protection.

For those devices that support virtualization-based security (VBS) features, including Credential Guard or protection of code integrity, this must be enabled. If the system meets the hardware and firmware dependencies for enabling VBS but it is not enabled, this is a CAT III finding.

Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"

If "RequiredSecurityProperties" does not include a value of "2" indicating "Secure Boot" (e.g., "{1, 2}"), this is a finding.

If "Secure Boot and DMA Protection" is configured, "3" will also be displayed in the results (e.g., "{1, 2, 3}").

If "VirtualizationBasedSecurityStatus" is not a value of "2" indicating "Running", this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "Device Guard virtualization-based security" does not display "Running", this is finding.

If "Device Guard Required Security Properties" does not display "Base Virtualization Support, Secure Boot", this is finding.

If "Secure Boot and DMA Protection" is configured, "DMA Protection" will also be displayed (e.g., "Base Virtualization Support, Secure Boot, DMA Protection").

The policy settings referenced in the Fix section will configure the following registry values. However due to hardware requirements, the registry values alone do not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\

Value Name: EnableVirtualizationBasedSecurity
Value Type: REG_DWORD
Value: 1

Value Name: RequirePlatformSecurityFeatures
Value Type: REG_DWORD
Value: 1 (Secure Boot only) or 3 (Secure Boot and DMA Protection)

A Microsoft article on Credential Guard system requirement can be found at the following link:

https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements
#>

# INCOMPLETE
return 'Not Reviewed'
