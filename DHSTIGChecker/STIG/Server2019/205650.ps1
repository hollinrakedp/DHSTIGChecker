# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205650
Rule ID:    SV-205650r890530_rule
STIG ID:    WN19-PK-000030
Legacy:     V-93491; SV-103577
Rule Title: Windows Server 2019 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems.
Discussion:
To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.

Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000403-GPOS-00182


Check Content:
This is applicable to unclassified systems. It is NA for others.

Open "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 AM                                                                                                                                                                                                                                                     
Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.

For each certificate with "US DoD CCEB Interoperability Root CA ..." under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 AM
#>

if ($Script:IsClassified) {
    Write-Verbose "Reason: Not an Unclassified System"
    return "Not Applicable"
}
else {
    $Certs = Get-ChildItem -Path "Cert:\LocalMachine\Disallowed\"
    $Thumbprints = @(
        "9B74964506C7ED9138070D08D5F8B969866560C8"
    )

    $Local:Results = Compare-Object -DifferenceObject $Certs.Thumbprint -ReferenceObject $Thumbprints -IncludeEqual -ExcludeDifferent

    if ($Local:Results.Count -eq $Thumbprints.Count) {
        $true
    }
    else {
        $false
    }
}