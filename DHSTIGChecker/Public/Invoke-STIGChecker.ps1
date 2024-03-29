function Invoke-STIGChecker {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({
                if ($_ -in (& $Script:TabCompleteAvailableSTIGs)) {
                    $true
                }
                else {
                    throw "Valid values: $((& $Script:TabCompleteAvailableSTIGs) -join ', ')"
                }
            })]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('Path')]
        [string]$ConfigPath
    )
    
    begin {
        try {
            $EnvConfig = Get-STIGCheckerConfig -Path "$ConfigPath"
        }
        catch {
            Write-Warning "Failed to get the Environment configuration file."
            break
        }
        
        try {
            $ComputerInfo = Get-STIGComputerInfo
        }
        catch {
            Write-Warning "Failed to get the Computer information."
            break
        }

        SecEdit.exe /Export  /cfg currentsecpolicy.txt | Out-Null
        $Script:CurrentSecPolicy = @{}
        Get-Content .\currentsecpolicy.txt | Where-Object { ($_ -match '=') -and ($_ -notmatch 'MACHINE') } | ForEach-Object { $Script:CurrentSecPolicy += ConvertFrom-StringData $_ }
        Remove-Item .\currentsecpolicy.txt
        
        $Script:AuditPolicy = Get-AdvancedAuditPolicy | Select-Object 'Subcategory', 'Inclusion Setting'
        $Script:HasBluetooth = Test-HasBluetooth
        $Script:DeviceGuard = Get-DeviceGuard
        $Script:IsClassified = $EnvConfig.IsClassified
        $Script:IsVDI = $EnvConfig.IsVDI
        $Script:VDINonPersist = $EnvConfig.VDINonPersist

        $Script:SIDLocalGroup = @{
            Administrators     = "S-1-5-32-544"
            Users              = "S-1-5-32-545"
            Guests             = "S-1-5-32-546"
            RemoteDesktopUsers = "S-1-5-32-555"
            Service            = "S-1-5-6"
            LocalService       = "S-1-5-19"
            NetworkService     = "S-1-5-20"
            LocalAccount       = "S-1-5-113"
        }

        $Script:IsDomainController = $ComputerInfo.CsDomainRole -like "*Domain*Controller"
        $Script:IsMemberServer = $ComputerInfo.CsDomainRole -like "*Member*Server"
        $Script:IsServerCore = $ComputerInfo.WindowsInstallationType -like "Server*Core"
        $Script:IsDomainJoined = $ComputerInfo.CsPartOfDomain

        if ($Script:IsDomainJoined) {
            Write-Verbose "System is joined to a Domain."
            Write-Verbose "Gathering needed Domain SIDs."
            try {
                $Script:SIDDomainGroup = @{
                    DomainAdmins     = $(Get-ADSIGroupSID -sAMAccountName 'Domain Admins')
                    EnterpriseAdmins = $(Get-ADSIGroupSID -sAMAccountName 'Enterprise Admins')
                }
            }
            catch {
                Write-Warning "Unable to gather Domain SIDs. Results may not be accurate."
            }
        }
        $STIGs = Get-ChildItem "$STIGRootPath\$Name\*" -File -Include "*.ps1"

        $VulnResults = @()

        #Initialize Counters
        [int]$STIGCounter = 0
        [int]$STIGCounterNA = 0
        [int]$STIGCounterO = 0
        [int]$STIGCounterNF = 0
        [int]$STIGCounterNR = 0
    }
    
    process {
        Write-Verbose "Found $($STIGS.Count) Checks."
        foreach ($STIG in $STIGs) {
            $STIGCounter++
            [int]$PercentComplete = [math]::Round(($STIGCounter / $STIGS.Count) * 100)
            Write-Progress -Activity "Running STIG Checks ($PercentComplete%)" -Status "Check: VulnID $($STIG.BaseName)" -PercentComplete $PercentComplete
            Write-Verbose "Check: $STIGCounter"
            Write-Verbose "Vulnerability ID: V-$($STIG.BaseName)"
            Write-Verbose "$($STIG.FullName)"
            [string]$result = . $STIG.FullName
            switch ($result) {
                True {
                    $STIGCounterNF++
                    $result = 'Not a Finding'
                }
                False {
                    $STIGCounterO++
                    $result = 'Open'
                }
                'Not Applicable' { $STIGCounterNA++ }
                'Not Reviewed' { $STIGCounterNR++ }
            }
            $VulnResults += [PSCustomObject]@{
                VulnID = "V-$($STIG.BaseName)"
                Result = $result
            }
        }

        Write-Verbose "Total Checks:    $STIGCounter"
        Write-Verbose "Open:            $STIGCounterO ($([math]::Round($($STIGCounterO/$STIGCounter*100)))%)"
        Write-Verbose "Not a Finding:   $STIGCounterNF ($([math]::Round($($STIGCounterNF/$STIGCounter*100)))%)"
        Write-Verbose "Not Reviewed:    $STIGCounterNR ($([math]::Round($($STIGCounterNR/$STIGCounter*100)))%)"
        Write-Verbose "Not Applicable:  $STIGCounterNA ($([math]::Round($($STIGCounterNA/$STIGCounter*100)))%)"
        
        #$VulnResults #| Group-Object -Property Result
        
        $ResultsCount = [ordered]@{
            'Not Applicable' = $STIGCounterNA
            'Not a Finding'  = $STIGCounterNF
            'Not Reviewed'   = $STIGCounterNR
            Open             = $STIGCounterO
            'Total Checks'   = $STIGCounter
        }
        $Score = [math]::Round((($STIGCounterNF / ($STIGCounterNF + $STIGCounterO + $STIGCounterNR))*100),2)

        $ResultsStatus = @{
            'Not Applicable' = ($VulnResults | Where-Object { $_.Result -eq 'Not Applicable' }).VulnID
            Open             = ($VulnResults | Where-Object { $_.Result -eq 'Open' }).VulnID
            'Not a Finding'  = ($VulnResults | Where-Object { $_.Result -eq 'Not a Finding' }).VulnID
            'Not Reviewed'   = ($VulnResults | Where-Object { $_.Result -eq 'Not Reviewed' }).VulnID
        }
        $STIGInfo = Get-Content "$STIGRootPath\$Name\version.json" | ConvertFrom-Json

        $STIGCheckerResults = @{
            ComputerName        = $env:COMPUTERNAME
            STIG                = $Name
            "STIG Release"      = "v$($STIGInfo.Version)r$($STIGInfo.Release)"
            "STIG Date"         = $STIGInfo.Date        
            Classified          = $Script:IsClassified
            'Domain Joined'     = $Script:IsDomainJoined
            'VDI System'        = $Script:IsVDI
            'Persistent VDI'    = $Script:VDINonPersist
            Score              = "$Score %"
            'Results Count'     = $ResultsCount
            'Results By Status' = $ResultsStatus
            Data                = $VulnResults
        }

        $STIGCheckerResults
    }
    
    end {
        
    }
}