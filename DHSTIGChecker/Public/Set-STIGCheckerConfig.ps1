function Set-STIGCheckerConfig {
    <#
    .SYNOPSIS
    Create a STIG Checker configuration file.

    .DESCRIPTION
    This function creates a configuration file for the STIG environment. This allows for appropriately evaluating additional STIG checks. Items such as the name of the local account created for administration, the users and groups that should be a member of the local Administrators group, etc.

    .NOTES
    Name         - Get-STIGCheckerConfig
    Version      - 0.1
    Author       - Darren Hollinrake
    Date Created - 2022-02-05
    Date Updated - 
    
    .PARAMETER IsClassified
    Use this parameter if the system is classified.

    .PARAMETER LocalAdminAccount
    The name of the local account on the system used to perform administrative tasks. This is NOT the name of the built-in administrator account.

    .PARAMETER MemberOfAdministrators
    Supply the users and groups that should be a member of the local Administators group.

    .PARAMETER IsVDI
    Use this parameter if the system is a part of a VDI implementation.

    .PARAMETER VDINonPersist
    Use this paramter if the system is a non-persistent VDI.

    .PARAMETER Path
    The path to save the configuration file for the system. If only a directory is specified, a default filename of 'STIGCheckerConfig-yyyyMMdd.json' will be used, where 'yyyyMMdd' is replaced with the current date.

    .EXAMPLE
    Set-STIGCheckerConfig -IsClassified -LocalAdminAccount Robin -Path "C:\temp\SystemConfig.json"
    This creates a configuration file named 'SystemConfig.json' in the 'C:\temp' directory. When this configuration file is used with 'Invoke-STIGChecker', it will evaluate the system as classified and with the local admin account named 'Robin'.
    
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$IsClassified,
        [Parameter(
            ValueFromPipelineByPropertyName,
            Mandatory)]
        [string]$LocalAdminAccount,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$MemberOfAdministrators,
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$IsVDI,
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$VDINonPersist,
        [Parameter(
            ValueFromPipelineByPropertyName,
            Mandatory)]
        [string]$Path
    )
    
    begin {
        
    }
    
    process {
        $Hashtable = @{
            IsClassified = $IsClassified.IsPresent
            LocalAdminAccountName = $LocalAdminAccount
            MemberOfAdministrators = $MemberOfAdministrators
            IsVDI = $IsVDI.IsPresent
            VDINonPersist = $VDINonPersist.IsPresent
        }

        $Config = [PSCustomObject]$Hashtable

        $JSON = $Config | ConvertTo-Json -Depth 4

        if ((Test-Path -Path $Path -PathType Container)) {
            Write-Verbose "Only a directory was provided. Using automatic filename."
            $FullPath = Join-Path -Path $Path -ChildPath "STIGCheckerConfig-$(Get-Date -Format yyyyMMdd).json"
        }
        elseif ((Test-Path -Path $Path -IsValid) -and ($Path -match '^*\.json')) {
            Write-Verbose "A full path was provided."
            $FullPath = $Path
            $ParentPath = Split-Path $Path
            if (!(Test-Path "$ParentPath")) {
                if ($PSCmdlet.ShouldProcess("$ParentPath", "New-Item")) {
                    Write-Verbose "Creating path: $ParentPath"
                    New-Item -Path $ParentPath -Force -ItemType Directory | Out-Null
                }
            }
        }
        else {
            Write-Warning "The provided path is not valid. Please provide a valid path to a file or directory."
            return
        }

        if ($PSCmdlet.ShouldProcess("$FullPath", "Out-File")) {
            Write-Output "Config file saved to: $FullPath"
            $JSON | Out-File $FullPath | Out-Null
        }
    }
    
    end {
        
    }
}