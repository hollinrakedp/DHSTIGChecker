<#
Rule Title: Windows Server 2019 PKI certificates associated with user accounts must be issued by a DoD PKI or an approved External Certificate Authority (ECA).
Severity: high
Vuln ID: V-205647
STIG ID: WN19-DC-000300

Discussion:
A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure. Without proper practices, the certificates issued by a CA have limited value in authentication functions.


Check Content:
This applies to domain controllers. It is NA for other systems.

Review user account mappings to PKI certificates.

Open "Windows PowerShell".

Enter "Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled".

Exclude disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

If the User Principal Name (UPN) is not in the format of an individual's identifier for the certificate type and for the appropriate domain suffix, this is a finding.

For standard NIPRNet certificates, the individual's identifier is in the format of an Electronic Data Interchange - Personnel Identifier (EDI-PI).

Alt Tokens and other certificates may use a different UPN format than the EDI-PI which vary by organization. Verified these with the organization.

NIPRNet Example:

Name - User Principal Name
User1 - 1234567890@mil

See PKE documentation for other network domain suffixes.

If the mappings are to certificates issued by a CA authorized by the Component's CIO, this is a CAT II finding.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}