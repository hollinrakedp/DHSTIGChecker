<#
Rule Title: Active Directory Group Policy objects must be configured with proper audit settings.
Severity: medium
Vuln ID: V-224980
STIG ID: WN16-DC-000170

Discussion:
When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data. The impact of missing audit data is related to the type of object. A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential. This includes Group Policy objects. Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain. The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212


Check Content:
This applies to domain controllers. It is NA for other systems.

Review the auditing configuration for all Group Policy objects.

Open "Group Policy Management" (available from various menus or run "gpmc.msc").

Navigate to "Group Policy Objects" in the domain being reviewed (Forest >> Domains >> Domain).

For each Group Policy object:

Select the Group Policy object item in the left pane.

Select the "Delegation" tab in the right pane.

Select the "Advanced" button.

Select the "Advanced" button again and then the "Auditing" tab.

If the audit settings for any Group Policy object are not at least as inclusive as those below, this is a finding.

Type - Fail
Principal - Everyone
Access - Full Control
Applies to - This object and all descendant objects or Descendant groupPolicyContainer objects

The three Success types listed below are defaults inherited from the Parent Object. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference.

Type - Success
Principal - Everyone
Access - Special (Permissions: Write all properties, Modify permissions; Properties: all "Write" type selected)
Inherited from - Parent Object
Applies to - Descendant groupPolicyContainer objects

Two instances with the following summary information will be listed.

Type - Success
Principal - Everyone
Access - blank (Permissions: none selected; Properties: one instance - Write gPLink, one instance - Write gPOptions)
Inherited from - Parent Object
Applies to - Descendant Organization Unit Objects

#>
return 'Not Reviewed'
