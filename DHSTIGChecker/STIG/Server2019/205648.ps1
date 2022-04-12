<#
Rule Title: Windows Server 2019 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.
Severity: medium
Vuln ID: V-205648
STIG ID: WN19-PK-000010

Discussion:
To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs. The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.

Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000403-GPOS-00182


Check Content:
The certificates and thumbprints referenced below apply to unclassified systems; see PKE documentation for other networks.

Open "Windows PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561
NotAfter: 12/5/2029

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
NotAfter: 12/30/2029

Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
NotAfter: 7/25/2032

Subject: CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
NotAfter: 6/14/2041

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".

For each of the DoD Root CA certificates noted below:

Right-click on the certificate and select "Open".

Select the "Details" Tab.

Scroll to the bottom and select "Thumbprint".

If the DoD Root CA certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

DoD Root CA 2
Thumbprint: 8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561
Valid to: Wednesday, December 5, 2029

DoD Root CA 3
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
Valid to: Sunday, December 30, 2029

DoD Root CA 4
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
Valid to: Sunday, July 25, 2032

DoD Root CA 5
Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
Valid to: Friday, June 14, 2041

#>

$Certs = Get-ChildItem -Path "Cert:LocalMachine\Root"
$Thumbprints = @(
    "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561",
    "D73CA91102A2204A36459ED32213B467D7CE97FB",
    "B8269F25DBD937ECAFD4C35A9838571723F2D026",
    "4ECB5CC3095670454DA1CBD410FC921F46B8564B"
)

$Local:Results = Compare-Object -DifferenceObject $Certs.Thumbprint -ReferenceObject $Thumbprints -IncludeEqual -ExcludeDifferent

if ($Local:Results.count -eq $Thumbprints.Count) {
    $true
}
else {
    $false
}