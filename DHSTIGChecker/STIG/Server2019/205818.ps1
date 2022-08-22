<#
Rule Title: Windows Server 2019 must use separate, NSA-approved (Type 1) cryptography to protect the directory data in transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data.
Severity: medium
Vuln ID: V-205818
STIG ID: WN19-DC-000140

Discussion:
Directory data that is not appropriately encrypted is subject to compromise. Commercial-grade encryption does not provide adequate protection when the classification level of directory data in transit is higher than the level of the network.


Check Content:
This applies to domain controllers. It is NA for other systems.

Review the organization network diagram(s) or documentation to determine the level of classification for the network(s) over which replication data is transmitted.

Determine the classification level of the Windows domain controller.

If the classification level of the Windows domain controller is higher than the level of the networks, review the organization network diagram(s) and directory implementation documentation to determine if NSA-approved encryption is used to protect the replication network traffic.

If the classification level of the Windows domain controller is higher than the level of the network traversed and NSA-approved encryption is not used, this is a finding.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}