# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253274
Rule ID:    SV-253274r840169_rule
STIG ID:    WN11-00-000095
Legacy:     
Rule Title: Permissions for system files and directories must conform to minimum requirements.
Discussion:
Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.


Check Content:
The default file system permissions are adequate when the Security Option "Network access: Let Everyone permissions apply to anonymous users" is set to "Disabled" (WN11-SO-000160).

If the default file system permissions are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the sample directories below. Non-privileged groups such as Users or Authenticated Users must not have greater than read & execute permissions except where noted as defaults. (Individual accounts must not be used to assign permissions.)

Viewing in File Explorer:
Select the "Security" tab, and the "Advanced" button.

C:\
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Administrators - Full control - This folder, subfolders, and files
SYSTEM - Full control - This folder, subfolders, and files
Users - Read & execute - This folder, subfolders, and files
Authenticated Users - Modify - Subfolders and files only
Authenticated Users - Create folders / append data - This folder only

\Program Files
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
TrustedInstaller - Full control - This folder and subfolders
SYSTEM - Modify - This folder only
SYSTEM - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders, and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files
ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files

\Windows
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
TrustedInstaller - Full control - This folder and subfolders
SYSTEM - Modify - This folder only
SYSTEM - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders, and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files
ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders, and files

Alternately use icacls.

Run "CMD" as administrator.
Enter "icacls" followed by the directory.

icacls c:\
icacls "c:\program files"
icacls c:\windows

The following results will be displayed as each is entered:

c:\
BUILTIN\Administrators:(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
NT AUTHORITY\Authenticated Users:(AD)
Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
Successfully processed 1 files; Failed processing 0 files

c:\program files 
NT SERVICE\TrustedInstaller:(F)
NT SERVICE\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(M)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(M)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
BUILTIN\Users:(RX)
BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files

c:\windows
NT SERVICE\TrustedInstaller:(F)
NT SERVICE\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(M)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(M)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
BUILTIN\Users:(RX)
BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files
#>

# INCOMPLETE
return 'Not Reviewed'
