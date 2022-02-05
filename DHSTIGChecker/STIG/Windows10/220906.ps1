<#
Rule Title: The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.
Severity: medium
Vuln ID: V-220906
STIG ID: WN10-PK-000020

Discussion:
To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.


Check Content:
Verify the US DoD CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an Untrusted Certificate.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint", information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S.Government, C=US
Thumbprint: AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9
NotAfter: 8/26/2022 9:07:50 AM

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Untrusted Certificates >> Certificates".

For each certificate with "US DoD CCEB Interoperability Root CA �" under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S.Government, C=US
Thumbprint: AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9
NotAfter: 8/26/2022 9:07:50 AM

#>

if ($Script:IsClassified) {
    Write-Verbose "This check does not apply: Reason - Not an Unclassified System"
    return "Not Applicable"
}
else {
    $Certs = Get-ChildItem -Path "Cert:\LocalMachine\Disallowed\"
    $Thumbprints = @(
        "AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9"
    )

    $Local:Results = Compare-Object -DifferenceObject $Certs.Thumbprint -ReferenceObject $Thumbprints -IncludeEqual -ExcludeDifferent

    if ($Local:Results.count -eq $Thumbprints.Count) {
        $true
    }
    else {
        $false
    }
}