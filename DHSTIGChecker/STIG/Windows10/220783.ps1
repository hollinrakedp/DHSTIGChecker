# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220783
Rule ID:    SV-220783r569187_rule
STIG ID:    WN10-AU-000520
Legacy:     V-63537; SV-78027
Rule Title: Windows 10 permissions for the Security event log must prevent access by non-privileged accounts.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The Security event log may disclose sensitive information or be  susceptible to tampering if proper permissions are not applied.


Check Content:
Verify the permissions on the Security event log (Security.evtx). Standard user accounts or groups must not have access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory. They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.

NOTE: If "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" has Special Permissions, this would not be a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
