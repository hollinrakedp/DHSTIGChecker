<#
Rule Title: Windows Server 2019 Active Directory Group Policy objects must have proper access control permissions.
Severity: high
Vuln ID: V-205741
STIG ID: WN19-DC-000090

Discussion:
When directory service database objects do not have appropriate access control permissions, it may be possible for malicious users to create, read, update, or delete the objects and degrade or destroy the integrity of the data. When the directory service is used for identification, authentication, or authorization functions, a compromise of the database objects could lead to a compromise of all systems relying on the directory service.

For Active Directory (AD), the Group Policy objects require special attention. In a distributed administration model (i.e., help desk), Group Policy objects are more likely to have access permissions changed from the secure defaults. If inappropriate access permissions are defined for Group Policy objects, this could allow an intruder to change the security policy applied to all domain client computers (workstations and servers).


Check Content:
This applies to domain controllers. It is NA for other systems.

Review the permissions on Group Policy objects.

Open "Group Policy Management" (available from various menus or run "gpmc.msc").

Navigate to "Group Policy Objects" in the domain being reviewed (Forest >> Domains >> Domain).

For each Group Policy object:

Select the Group Policy object item in the left pane.

Select the "Delegation" tab in the right pane.

Select the "Advanced" button.

Select each Group or user name.

View the permissions.

If any standard user accounts or groups have "Allow" permissions greater than "Read" and "Apply group policy", this is a finding.

Other access permissions that allow the objects to be updated are considered findings unless specifically documented by the ISSO.

The default permissions noted below satisfy this requirement. 

The permissions shown are at the summary level. More detailed permissions can be viewed by selecting the next "Advanced" button, the desired Permission entry, and the "Edit" button.

Authenticated Users - Read, Apply group policy, Special permissions

The special permissions for Authenticated Users are for Read-type Properties. If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

The special permissions for the following default groups are not the focus of this requirement and may include a wide range of permissions and properties:

CREATOR OWNER - Special permissions
SYSTEM - Read, Write, Create all child objects, Delete all child objects, Special permissions
Domain Admins - Read, Write, Create all child objects, Delete all child objects, Special permissions
Enterprise Admins - Read, Write, Create all child objects, Delete all child objects, Special permissions
ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

The Domain Admins and Enterprise Admins will not have the "Delete all child objects" permission on the two default Group Policy objects: Default Domain Policy and Default Domain Controllers Policy. They will have this permission on organization created Group Policy objects.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}