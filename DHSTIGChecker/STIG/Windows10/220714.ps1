<#
Rule Title: Only authorized user accounts must be allowed to create or run virtual machines on Windows 10 systems.
Severity: medium
Vuln ID: V-220714
STIG ID: WN10-00-000080

Discussion:
Allowing other operating systems to run on a secure system may allow users to circumvent security. For Hyper-V, preventing unauthorized users from being assigned to the Hyper-V Administrators group will prevent them from accessing or creating virtual machines on the system. The Hyper-V Hypervisor is used by Virtualization Based Security features such as Credential Guard on Windows 10; however, it is not the full Hyper-V installation.


Check Content:
If a hosted hypervisor (Hyper-V, VMware Workstation, etc.) is installed on the system, verify only authorized user accounts are allowed to run virtual machines.

For Hyper-V, Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Double click on "Hyper-V Administrators".

If any unauthorized groups or user accounts are listed in "Members:", this is a finding.

For hosted hypervisors other than Hyper-V, verify only authorized user accounts have access to run the virtual machines. Restrictions may be enforced by access to the physical system, software restriction policies, or access restrictions built in to the application.

If any unauthorized groups or user accounts have access to create or run virtual machines, this is a finding.

All users authorized to create or run virtual machines must be documented with the ISSM/ISSO. Accounts nested within group accounts must be documented as individual accounts and not the group accounts.

#>

#Incomplete
return "Not Reviewed"