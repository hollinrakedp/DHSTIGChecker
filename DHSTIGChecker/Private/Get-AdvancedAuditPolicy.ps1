function Get-AdvancedAuditPolicy {
    <#
    .SYNOPSIS
    Retreive the audit policy.

    .DESCRIPTION
    This function will retreive the local system audit policy.

    .NOTES
    Name         - Get-AdvancedAuditPolicy
    Version      - 0.2
    Author       - Darren Hollinrake
    Date Created - 2022-01-16
    Date Updated - 2022-02-04

    .EXAMPLE
    Get-AdvancedAuditPolicy

    Machine Name      : Computer91
    Policy Target     : System
    Subcategory       : IPsec Driver
    Subcategory GUID  : {0CCE9213-69AE-11D9-BED3-505054503030}
    Inclusion Setting : No Auditing
    Exclusion Setting :

    Machine Name      : Computer91
    Policy Target     : System
    Subcategory       : Other System Events
    Subcategory GUID  : {0CCE9214-69AE-11D9-BED3-505054503030}
    Inclusion Setting : Success and Failure
    Exclusion Setting :

    Machine Name      : Computer91
    Policy Target     : System
    Subcategory       : Security State Change
    Subcategory GUID  : {0CCE9210-69AE-11D9-BED3-505054503030}
    Inclusion Setting : Success
    Exclusion Setting :
    #>
    
    param ()
    auditpol /get /category:* /r | ConvertFrom-Csv
}