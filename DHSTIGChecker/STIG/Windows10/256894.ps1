# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-256894
Rule ID:    SV-256894r891287_rule
STIG ID:    WN10-CC-000391
Legacy:     
Rule Title: Internet Explorer must be disabled for Windows 10.
Discussion:
Internet Explorer 11 (IE11) is no longer supported on Windows 10 semi-annual channel. 


Check Content:
Determine if IE11 is installed or enabled on Windows 10 semi-annual channel.

If IE11 is installed or not disabled on Windows 10 semi-annual channel, this is a finding.

If IE11 is installed on a unsupported operating system and is enabled or installed, this is a finding.

For more information, visit: https://learn.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge#what-is-the-lifecycle-policy-for-internet-explorer-
#>

# INCOMPLETE
return 'Not Reviewed'
