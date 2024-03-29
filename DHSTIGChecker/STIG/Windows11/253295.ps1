# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253295
Rule ID:    SV-253295r890452_rule
STIG ID:    WN11-00-000250
Legacy:     
Rule Title: Windows 11 nonpersistent VM sessions must not exceed 24 hours.
Discussion:
For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization must enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.


Check Content:
Verify there is a documented policy or procedure in place that nonpersistent VM sessions do not exceed 24 hours.                                                                                                                                                                                                                                                                                                  

If the system is NOT a nonpersistent VM, this is Not Applicable. 

For Azure Virtual Desktop (AVD) implementations with no data at rest, this is Not Applicable.

If there is no such documented policy or procedure in place, this is a finding.
#>

# MANUAL
return 'Not Reviewed'
