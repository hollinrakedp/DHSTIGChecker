# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205848
Rule ID:    SV-205848r902429_rule
STIG ID:    WN19-00-000090
Legacy:     V-93213; SV-103301
Rule Title: Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
Discussion:
Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. A number of system requirements must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.


Check Content:
For standalone or nondomain-joined systems, this is NA.

Verify the system has a TPM and it is ready for use.

Run "tpm.msc".

Review the sections in the center pane.

"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".

TPM Manufacturer Information - Specific Version = 2.0 or 1.2

If a TPM is not found or is not ready for use, this is a finding.
#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

$TPM = Get-Tpm

if ($TPM.Present) {
    if ($TPM.Ready) {
        if ($TPM.Enabled) {
            Write-Verbose "Reason: TPM is Enabled"
            $true
        }
        else {
            Write-Verbose "Reason: TPM Not Enabled"
            $false
        }
    }
    else {
        Write-Verbose "Reason: TPM Not Ready"
        $false
    }
}
else {
    Write-Verbose "Reason: TPM Not Present"
    $false
}