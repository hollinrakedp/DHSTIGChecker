<#
Rule Title: Windows 10 non-persistent VM sessions should not exceed 24 hours. 
Severity: medium
Vuln ID: V-220738
STIG ID: WN10-00-000250

Discussion:
For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization should enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.


Check Content:
Ensure there is a documented policy or procedure in place that non-persistent VM sessions do not exceed 24 hours.

If there is no such documented policy or procedure in place, this is a finding.

#>
if ($Script:isVDI -and !$Script:VDIPersist) {
    return "Not Reviewed"
}
else {
    Write-Verbose "This check does not apply: Reason - Not a Non-Persistent VDI System"
    return "Not Applicable"
}