# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224823
Rule ID:    SV-224823r569186_rule
STIG ID:    WN16-00-000060
Legacy:     V-73229; SV-87881
Rule Title: Manually managed application account passwords must be at least 15 characters in length.
Discussion:
Application/service account passwords must be of sufficient length to prevent being easily cracked. Application/service accounts that are manually managed must have passwords at least 15 characters in length.


Check Content:
Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.

If such a policy does not exist or has not been implemented, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
