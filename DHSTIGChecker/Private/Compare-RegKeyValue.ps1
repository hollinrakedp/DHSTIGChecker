function Compare-RegKeyValue {
    <#
    .SYNOPSIS
    Compares the given registry key value against the provided value.

    .DESCRIPTION
    This function will retreive a registry key value and compare it against he supplied value. If they match, the function returns '$true'. If they do not match OR the value does not exist, it will return '$false'. If the value to be compared is a number, the operator can be 'le' or 'ge' for the comparison.

    .NOTES
    Name         - Compare-RegKeyValue
    Version      - 0.1
    Author       - Darren Hollinrake
    Date Created - 2022-01-16
    Date Updated - 

    .PARAMETER Path
    The path to the registry key. It should begin with 'HKCU:\' or 'HKLM:\'

    .PARAMETER Name
    The name of the Key whose value will be compared.

    .PARAMETER ExpectedValue
    The expected value of the Key Name specified. This will be the value compared to the actual value.

    .EXAMPLE
    Compare-RegKeyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" -Name "AllowBasicAuthInClear" -ExpectedValue 0
    true

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$Path,
        [Parameter(Mandatory)]
        [String]$Name,
        [Parameter(Mandatory)]
        $ExpectedValue,
        [Parameter()]
        [ValidateSet("like", "ge", "le", "ne")]
        $Comparison = "like"
    )

    $Exists = Test-RegKeyValueExists -Path $Path -Name $Name

    if ($Exists) {
        $CurrentValue = Get-ItemProperty -Path $Path -Name $Name
        Write-Verbose -Message "Key Value: $($CurrentValue.Name)"
        $result = switch ($Comparison) {
            like { $CurrentValue.$Name -like $ExpectedValue }
            ge { $CurrentValue.$Name -ge $ExpectedValue }
            le { $CurrentValue.$Name -le $ExpectedValue }
            ne { $CurrentValue.$Name -ne $ExpectedValue }
        }
    }
    else {
        Write-Verbose -Message "Value: Does not exist"
        $result = $false
    }

    $result
}