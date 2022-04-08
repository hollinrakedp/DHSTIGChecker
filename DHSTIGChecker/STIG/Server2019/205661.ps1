<#
Rule Title: Windows Server 2019 manually managed application account passwords must be at least 15 characters in length.
Severity: medium
Vuln ID: V-205661
STIG ID: WN19-00-000050

Discussion:
Application/service account passwords must be of sufficient length to prevent being easily cracked. Application/service accounts that are manually managed must have passwords at least 15 characters in length.


Check Content:
Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.

If such a policy does not exist or has not been implemented, this is a finding.

#>
return 'Not Reviewed'
