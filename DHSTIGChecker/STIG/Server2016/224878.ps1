<#
Rule Title: Permissions for the Security event log must prevent access by non-privileged accounts.
Severity: medium
Vuln ID: V-224878
STIG ID: WN16-AU-000040

Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Security event log may disclose sensitive information or be susceptible to tampering if proper permissions are not applied.

Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029


Check Content:
Navigate to the Security event log file.

The default location is the "%SystemRoot%\System32\winevt\Logs" folder. However, the logs may have been moved to another folder.

If the permissions for the "Security.evtx" file are not as restrictive as the default permissions listed below, this is a finding.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

#>
return 'Not Reviewed'
