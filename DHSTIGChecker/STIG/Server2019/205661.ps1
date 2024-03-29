# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205661
Rule ID:    SV-205661r569188_rule
STIG ID:    WN19-00-000050
Legacy:     V-93461; SV-103547
Rule Title: Windows Server 2019 manually managed application account passwords must be at least 15 characters in length.
Discussion:
Application/service account passwords must be of sufficient length to prevent being easily cracked. Application/service accounts that are manually managed must have passwords at least 15 characters in length.


Check Content:
Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.

If such a policy does not exist or has not been implemented, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
