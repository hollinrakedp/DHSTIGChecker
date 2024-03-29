# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253351
Rule ID:    SV-253351r829137_rule
STIG ID:    WN11-CC-000007
Legacy:     
Rule Title: Windows 11 must cover or disable the built-in or attached camera when not in use.
Discussion:
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect from collaborative computing devices (i.e. cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure that participants actually carry out the disconnect activity without having to go through complex and tedious procedures.

Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155


Check Content:
If the device or operating system does not have a camera installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of the camera is a local AO decision.

This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are centrally managed.

For an external camera, if there is not a method for the operator to manually disconnect camera at the end of collaborative computing sessions, this is a finding.

For a built-in camera, the camera must be protected by a camera cover (e.g. laptop camera cover slide) when not in use. If the built-in camera is not protected with a camera cover, or if the built-in
camera is not disabled in the bios, this is a finding.

If the camera is not disconnected or covered, the following registry entry is required:

Registry Hive: HKEY_LOCAL_MACHINE
RegistryPath\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam

Value Name: Deny

If "Value Name" is set to a value other than "Deny" and the collaborative computing device has not been authorized for use, this is a finding.
#>

# PARTIAL
$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\"
    Name = "Value"
    ExpectedValue = "Deny"
}

Compare-RegKeyValue @Params