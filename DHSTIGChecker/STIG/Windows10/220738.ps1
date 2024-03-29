# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220738
Rule ID:    SV-220738r890426_rule
STIG ID:    WN10-00-000250
Legacy:     V-102611; SV-111557
Rule Title: Windows 10 nonpersistent VM sessions must not exceed 24 hours. 
Discussion:
For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization should enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.


Check Content:
Ensure there is a documented policy or procedure in place that nonpersistent VM sessions do not exceed 24 hours. If the system is NOT a nonpersistent VM, this is Not Applicable.

If no such documented policy or procedure is in place, this is a finding.
#>

# PARTIAL
if ($Script:isVDI -and !$Script:VDIPersist) {
    return "Not Reviewed"
}
else {
    Write-Verbose "Reason: Not a Non-Persistent VDI System"
    return "Not Applicable"
}