# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224982
Rule ID:    SV-224982r852354_rule
STIG ID:    WN16-DC-000190
Legacy:     V-73393; SV-88045
Rule Title: The Active Directory Infrastructure object must be configured with proper audit settings.
Discussion:
When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data. The impact of missing audit data is related to the type of object. A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential. This includes the Infrastructure object. Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain. The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212


Check Content:
This applies to domain controllers. It is NA for other systems.

Review the auditing configuration for Infrastructure object.

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").

Ensure "Advanced Features" is selected in the "View" menu.

Select the domain being reviewed in the left pane.

Right-click the "Infrastructure" object in the right pane and select "Properties".

Select the "Security" tab.

Select the "Advanced" button and then the "Auditing" tab.

If the audit settings on the Infrastructure object are not at least as inclusive as those below, this is a finding.

Type - Fail
Principal - Everyone
Access - Full Control
Inherited from - None

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference. Various Properties selections may also exist by default.

Type - Success
Principal - Everyone
Access - Special
Inherited from - None
(Access - Special = Permissions: Write all properties, All extended rights, Change infrastructure master)

Two instances with the following summary information will be listed.
Type - Success
Principal - Everyone
Access - (blank)
Inherited from - (CN of domain)
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}