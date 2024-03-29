# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220904
Rule ID:    SV-220904r894652_rule
STIG ID:    WN10-PK-000010
Legacy:     V-63583; SV-78073
Rule Title: The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems.
Discussion:
To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly validated, the system must trust the ECA Root CAs. The ECA root certificates will ensure the trust chain is established for server certificates issued from the External CAs. This requirement only applies to unclassified systems.


Check Content:
Verify the ECA Root CA certificates are installed on unclassified systems as Trusted Root Certification Authorities.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter

If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US
Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582
NotAfter: 12/30/2029

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".

For each of the ECA Root CA certificates noted below:

Right-click on the certificate and select "Open".

Select the "Details" Tab.

Scroll to the bottom and select "Thumbprint".

If the ECA Root CA certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

ECA Root CA 4
Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582
Valid to: Sunday, December 30, 2029
#>

if ($Script:IsClassified) {
    Write-Verbose "Reason: Not an Unclassified System"
    return "Not Applicable"
}
else {
    $Certs = Get-ChildItem -Path "Cert:LocalMachine\Root"
    $Thumbprints = @(
        "73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582"
    )

    $Local:Results = Compare-Object -DifferenceObject $Certs.Thumbprint -ReferenceObject $Thumbprints -IncludeEqual -ExcludeDifferent

    if ($Local:Results.count -eq $Thumbprints.Count) {
        $true
    }
    else {
        $false
    }
}