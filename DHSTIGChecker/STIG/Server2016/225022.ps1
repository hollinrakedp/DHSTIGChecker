# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225022
Rule ID:    SV-225022r894338_rule
STIG ID:    WN16-PK-000020
Legacy:     V-73607; SV-88271
Rule Title: The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.
Discussion:
To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.

Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000403-GPOS-00182


Check Content:
Verify the DoD Interoperability cross-certificates are installed on unclassified systems as Untrusted Certificates.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 49CBE933151872E17C8EAE7F0ABA97FB610F6477
NotAfter: 11/16/2024 9:57:16 AM

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.

For each certificate with "DoD Root CA…" under "Issued To" and "DoD Interoperability Root CA…" under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

If an expired certificate ("Valid to" date) is not listed in the results, this is not a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 49CBE933151872E17C8EAE7F0ABA97FB610F6477
NotAfter: 11/16/2024 9:57:16 AM
#>

if ($Script:IsClassified) {
    Write-Verbose "Reason: Not an Unclassified System"
    return "Not Applicable"
}
else {
    $Certs = Get-ChildItem -Path "Cert:\LocalMachine\Disallowed\"
    $Thumbprints = @(
        "49CBE933151872E17C8EAE7F0ABA97FB610F6477"
    )

    $Local:Results = Compare-Object -DifferenceObject $Certs.Thumbprint -ReferenceObject $Thumbprints -IncludeEqual -ExcludeDifferent

    if ($Local:Results.count -eq $Thumbprints.Count) {
        $true
    }
    else {
        $false
    }
}