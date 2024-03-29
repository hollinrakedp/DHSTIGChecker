# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224877
Rule ID:    SV-224877r569186_rule
STIG ID:    WN16-AU-000030
Legacy:     V-73405; SV-88057
Rule Title: Permissions for the Application event log must prevent access by non-privileged accounts.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Application event log may be susceptible to tampering if proper permissions are not applied.

Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029


Check Content:
Navigate to the Application event log file.

The default location is the "%SystemRoot%\System32\winevt\Logs" folder. However, the logs may have been moved to another folder.

If the permissions for the "Application.evtx" file are not as restrictive as the default permissions listed below, this is a finding.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control
#>

# INCOMPLETE
return 'Not Reviewed'
