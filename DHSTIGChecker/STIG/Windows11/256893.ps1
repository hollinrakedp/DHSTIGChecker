# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-256893
Rule ID:    SV-256893r892440_rule
STIG ID:    WN11-CC-000391
Legacy:     
Rule Title: Internet Explorer must be disabled for Windows 11.
Discussion:
Internet Explorer 11 (IE11) is not supported on Windows 11 semi-annual channel.


Check Content:
Determine if IE11 is installed or enabled on Windows 11 semi-annual channel.

If IE11 is installed or not disabled on Windows 11 semi-annual channel, this is a finding.

If IE11 is installed on an unsupported operating system and is enabled or installed, this is a finding.

For more information, visit: https://learn.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge#what-is-the-lifecycle-policy-for-internet-explorer-
#>

# INCOMPLETE
return 'Not Reviewed'
