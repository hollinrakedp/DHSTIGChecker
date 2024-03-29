# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205695
Rule ID:    SV-205695r569188_rule
STIG ID:    WN19-DC-000130
Legacy:     V-93417; SV-103503
Rule Title: Windows Server 2019 domain controllers must run on a machine dedicated to that function.
Discussion:
Executing application servers on the same host machine with a directory server may substantially weaken the security of the directory server. Web or database server applications usually require the addition of many programs and accounts, increasing the attack surface of the computer. 

Some applications require the addition of privileged accounts, providing potential sources of compromise. Some applications (such as Microsoft Exchange) may require the use of network ports or services conflicting with the directory server. In this case, non-standard ports might be selected, and this could interfere with intrusion detection or prevention services.


Check Content:
This applies to domain controllers, it is NA for other systems.

Review the installed roles the domain controller is supporting.

Start "Server Manager".

Select "AD DS" in the left pane and the server name under "Servers" to the right.

Select "Add (or Remove) Roles and Features" from "Tasks" in the "Roles and Features" section. (Cancel before any changes are made.)

Determine if any additional server roles are installed. A basic domain controller setup will include the following:

- Active Directory Domain Services
- DNS Server
- File and Storage Services

If any roles not requiring installation on a domain controller are installed, this is a finding. 

A Domain Name System (DNS) server integrated with the directory server (e.g., AD-integrated DNS) is an acceptable application. However, the DNS server must comply with the DNS STIG security requirements.

Run "Programs and Features".

Review installed applications.

If any applications are installed that are not required for the domain controller, this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}