<#
Rule Title: Windows Server 2019 domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority (ECA).
Severity: high
Vuln ID: V-205646
STIG ID: WN19-DC-000290

Discussion:
A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure. Without proper practices, the certificates issued by a CA have limited value in authentication functions. The use of multiple CAs from separate PKI implementations results in interoperability issues. If servers and clients do not have a common set of root CA certificates, they are not able to authenticate each other.


Check Content:
This applies to domain controllers. It is NA for other systems.

Run "MMC".

Select "Add/Remove Snap-in" from the "File" menu.

Select "Certificates" in the left pane and click the "Add >" button.

Select "Computer Account" and click "Next".

Select the appropriate option for "Select the computer you want this snap-in to manage" and click "Finish".

Click "OK".

Select and expand the Certificates (Local Computer) entry in the left pane.

Select and expand the Personal entry in the left pane.

Select the Certificates entry in the left pane.

In the right pane, examine the "Issued By" field for the certificate to determine the issuing CA.

If the "Issued By" field of the PKI certificate being used by the domain controller does not indicate the issuing CA is part of the DoD PKI or an approved ECA, this is a finding.

If the certificates in use are issued by a CA authorized by the Component's CIO, this is a CAT II finding.

There are multiple sources from which lists of valid DoD CAs and approved ECAs can be obtained: 

The Global Directory Service (GDS) website provides an online source. The address for this site is https://crl.gds.disa.mil.

DoD Public Key Enablement (PKE) Engineering Support maintains the InstallRoot utility to manage DoD supported root certificates on Windows computers, which includes a list of authorized CAs. The utility package can be downloaded from the PKI and PKE Tools page on IASE:

http://iase.disa.mil/pki-pke/function_pages/tools.html

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}