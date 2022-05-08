<#
Rule Title: Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
Severity: medium
Vuln ID: V-205848
STIG ID: WN19-00-000090

Discussion:
Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. A number of system requirements must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.


Check Content:
For standalone systems, this is NA.

Current hardware and virtual environments may not support virtualization-based security features, including Credential Guard, due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within a virtual machine.

Verify the system has a TPM and it is ready for use.

Run "tpm.msc".

Review the sections in the center pane.

"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".

TPM Manufacturer Information - Specific Version = 2.0 or 1.2

If a TPM is not found or is not ready for use, this is a finding.

#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}

$TPM = Get-Tpm

if ($TPM.Present) {
    if ($TPM.Ready) {
        if ($TPM.Enabled) {
            Write-Verbose "Pass: Reason - TPM is Enabled"
            $true
        }
        else {
            Write-Verbose "Fail: Reason - TPM Not Enabled"
            $false
        }
    }
    else {
        Write-Verbose "Fail: Reason - TPM Not Ready"
        $false
    }
}
else {
    Write-Verbose "Fail: Reason - TPM Not Present"
    $false
}