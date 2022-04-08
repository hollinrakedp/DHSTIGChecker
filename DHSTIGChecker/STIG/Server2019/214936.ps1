<#
Rule Title: Windows Server 2019 must have a host-based firewall installed and enabled.
Severity: medium
Vuln ID: V-214936
STIG ID: WN19-00-000280

Discussion:
A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.


Check Content:
Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.

#>
return 'Not Reviewed'
