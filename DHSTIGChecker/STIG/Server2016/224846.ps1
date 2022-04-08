<#
Rule Title: A host-based firewall must be installed and enabled on the system.
Severity: medium
Vuln ID: V-224846
STIG ID: WN16-00-000310

Discussion:
A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.


Check Content:
Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.

#>
return 'Not Reviewed'
