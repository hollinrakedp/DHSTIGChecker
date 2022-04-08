<#
Rule Title: Windows Server 2019 shared user accounts must not be permitted.
Severity: medium
Vuln ID: V-205699
STIG ID: WN19-00-000070

Discussion:
Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate identification and authentication. There is no way to provide for nonrepudiation or individual accountability for system access and resource usage.


Check Content:
Determine whether any shared accounts exist. If no shared accounts exist, this is NA.

Shared accounts, such as required by an application, may be approved by the organization.  This must be documented with the ISSO. Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.

If unapproved shared accounts exist, this is a finding.

#>
return 'Not Reviewed'
