<#
Rule Title: Windows Server 2019 permissions on the Active Directory data files must only allow System and Administrators access.
Severity: high
Vuln ID: V-205739
STIG ID: WN19-DC-000070

Discussion:
Improper access permissions for directory data-related files could allow unauthorized users to read, modify, or delete directory data or audit trails.


Check Content:
This applies to domain controllers. It is NA for other systems.

Run "Regedit".

Navigate to "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters".

Note the directory locations in the values for:

Database log files path
DSA Database file

By default, they will be \Windows\NTDS.

If the locations are different, the following will need to be run for each.

Open "Command Prompt (Admin)".

Navigate to the NTDS directory (\Windows\NTDS by default).

Run "icacls *.*".

If the permissions on each file are not as restrictive as the following, this is a finding:

NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}