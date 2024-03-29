# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253255
Rule ID:    SV-253255r877465_rule
STIG ID:    WN11-00-000010
Legacy:     
Rule Title: Windows 11 domain-joined systems must have a Trusted Platform Module (TPM) enabled.
Discussion:
Credential Guard uses virtualization-based security to protect information that could be used in credential theft attacks if compromised. There are a number of system requirements that must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.


Check Content:
Verify domain-joined systems have a TPM enabled and ready for use.

For standalone systems, this is NA.

Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system has a TPM and is ready for use.
Run "tpm.msc".
Review the sections in the center pane.
"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".
TPM Manufacturer Information - Specific Version = 2.0

If a TPM is not found or is not ready for use, this is a finding.
#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

if ($Script:isVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "Reason: Non-Persistent VDI"
        return "Not Applicable"
    }
}

$TPM = Get-Tpm

if ($TPM.Present) {
    if ($TPM.Ready) {
        if ($TPM.Enabled) {
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