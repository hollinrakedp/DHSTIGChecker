<#
Rule Title: Windows Server 2019 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.
Severity: medium
Vuln ID: V-205705
STIG ID: WN19-DC-000050

Discussion:
This setting determines the period of time (in days) during which a user's Ticket Granting Ticket (TGT) may be renewed. This security configuration limits the amount of time an attacker has to crack the TGT and gain access.

Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain).
 
Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum lifetime for user ticket renewal" is greater than "7" days, this is a finding.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}