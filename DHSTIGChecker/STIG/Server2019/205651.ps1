# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205651
Rule ID:    SV-205651r569188_rule
STIG ID:    WN19-SO-000350
Legacy:     V-93493; SV-103579
Rule Title: Windows Server 2019 users must be required to enter a password to access private keys stored on the computer.
Discussion:
If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Cryptography\

Value Name:  ForceKeyProtection

Type:  REG_DWORD
Value:  0x00000002 (2)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\"
    Name          = "ForceKeyProtection"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params