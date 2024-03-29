# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205734
Rule ID:    SV-205734r852432_rule
STIG ID:    WN19-00-000140
Legacy:     V-93019; SV-103107
Rule Title: Windows Server 2019 permissions for the system drive root directory (usually C:\) must conform to minimum requirements.
Discussion:
Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.

The default permissions are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (WN19-SO-000240).

Satisfies: SRG-OS-000312-GPOS-00122, SRG-OS-000312-GPOS-00123, SRG-OS-000312-GPOS-00124


Check Content:
The default permissions are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (WN19-SO-000240).

Review the permissions for the system drive's root directory (usually C:\). Non-privileged groups such as Users or Authenticated Users must not have greater than "Read & execute" permissions except where noted as defaults. Individual accounts must not be used to assign permissions.

If permissions are not as restrictive as the default permissions listed below, this is a finding.

Viewing in File Explorer:

View the Properties of the system drive's root directory.

Select the "Security" tab, and the "Advanced" button.

Default permissions:
C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders, and files
Administrators - Full control - This folder, subfolders, and files
Users - Read & execute - This folder, subfolders, and files
Users - Create folders/append data - This folder and subfolders
Users - Create files/write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only

Alternately, use icacls:

Open "Command Prompt (Admin)".

Enter "icacls" followed by the directory:

"icacls c:\"

The following results should be displayed:

c:\
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Administrators:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
BUILTIN\Users:(CI)(AD)
BUILTIN\Users:(CI)(IO)(WD)
CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files
#>

# INCOMPLETE
return 'Not Reviewed'
