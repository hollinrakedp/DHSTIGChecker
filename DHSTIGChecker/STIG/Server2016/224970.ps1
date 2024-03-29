# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224970
Rule ID:    SV-224970r877392_rule
STIG ID:    WN16-DC-000070
Legacy:     V-73369; SV-88021
Rule Title: Permissions on the Active Directory data files must only allow System and Administrators access.
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

If the permissions on each file are not as restrictive as the following, this is a finding.

NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}