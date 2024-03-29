# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253259
Rule ID:    SV-253259r877379_rule
STIG ID:    WN11-00-000030
Legacy:     
Rule Title: Windows 11 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.
Discussion:
If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running.


Check Content:
Verify all Windows 11 information systems (including SIPRNet) employ BitLocker for full disk encryption.

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
For AVD implementations with no data at rest, this is NA.

If full disk encryption using BitLocker is not implemented, this is a finding.

Verify BitLocker is turned on for the operating system drive and any fixed data drives.

Open "BitLocker Drive Encryption" from the Control Panel.

If the operating system drive or any fixed data drives have "Turn on BitLocker", this is a finding.

Note: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full disk encryption and satisfies the pre-boot authentication requirements (WN11-00-000031 and WN11-00-000032).
#>

if ($Script:IsVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "Reason: Non-Persistent VDI"
        return "Not Applicable"
    }
}

$FixedDrives = (Get-Volume | Where-Object {($_.DriveType -eq 'Fixed') -and ($null -ne $_.DriveLetter)} | Select-Object DriveLetter).DriveLetter

$Local:Results = @()

foreach ($Drive in $FixedDrives) {
    $BitlockerVolume = Get-BitLockerVolume -MountPoint "$Drive`:"
    switch ($BitlockerVolume.VolumeStatus) {
        FullyEncrypted {
            $Local:Results += $true
            continue
        }
        EncryptionInProgress {
            $Local:Results += $true
            continue
        }
        Default {
            $Local:Results += $false
        }
    }
}

if ($Local:Results -contains $false) {
    return $false
}
else {
    return $true
}