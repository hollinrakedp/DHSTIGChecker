# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220725
Rule ID:    SV-220725r569187_rule
STIG ID:    WN10-00-000140
Legacy:     V-63403; SV-77893
Rule Title: Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts.
Discussion:
Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised.  Limiting inbound connections only from authorized remote management systems will help limit this exposure.


Check Content:
Verify firewall exceptions to inbound connections on domain workstations include only authorized remote management hosts.

If allowed inbound exceptions are not limited to authorized remote management hosts, this is a finding.

Review inbound firewall exceptions.
Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right pane)

For any inbound rules that allow connections view the Scope for Remote IP address. This may be defined as an IP address, subnet, or range. The rule must apply to all firewall profiles.

If a third-party firewall is used, ensure comparable settings are in place.
#>

# INCOMPLETE
return 'Not Reviewed'
