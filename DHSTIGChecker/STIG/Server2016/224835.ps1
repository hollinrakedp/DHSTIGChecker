# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224835
Rule ID:    SV-224835r877392_rule
STIG ID:    WN16-00-000190
Legacy:     V-73255; SV-87907
Rule Title: Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.
Discussion:
The registry is integral to the function, security, and stability of the Windows system. Changing the system's registry permissions allows the possibility of unauthorized and anonymous modification to the operating system.


Check Content:
Review the registry permissions for the keys of the HKEY_LOCAL_MACHINE hive noted below.

If any non-privileged groups such as Everyone, Users, or Authenticated Users have greater than Read permission, this is a finding.

If permissions are not as restrictive as the default permissions listed below, this is a finding.

Run "Regedit".

Right-click on the registry areas noted below.

Select "Permissions..." and the "Advanced" button.

HKEY_LOCAL_MACHINE\SECURITY

Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
SYSTEM - Full Control - This key and subkeys
Administrators - Special - This key and subkeys

HKEY_LOCAL_MACHINE\SOFTWARE

Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Users - Read - This key and subkeys
Administrators - Full Control - This key and subkeys
SYSTEM - Full Control - This key and subkeys
CREATOR OWNER - Full Control - This key and subkeys
ALL APPLICATION PACKAGES - Read - This key and subkeys

HKEY_LOCAL_MACHINE\SYSTEM

Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Users - Read - This key and subkeys
Administrators - Full Control - This key and subkeys
SYSTEM - Full Control - This key and subkeys
CREATOR OWNER - Full Control - Subkeys only
ALL APPLICATION PACKAGES - Read - This key and subkeys
Server Operators – Read – This Key and subkeys    (Domain controllers only) 

Other examples under the noted keys may also be sampled. There may be some instances where non-privileged groups have greater than Read permission.

If the defaults have not been changed, these are not a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
