
function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity,

        [Parameter()]
        [System.String[]]
        $AccessTokens
    )

    try {
        $ConnectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
            -InboundParameters $PSBoundParameters
        Write-Verbose -Message "Getting configuration of the Intune Policy Sets with DisplayName {$DisplayName}"
        #Ensure the proper dependencies are installed in the current environment.
        #Confirm-M365DSCDependencies

        #region Telemetry
        $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
        $CommandName = $MyInvocation.MyCommand
        $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
            -CommandName $CommandName `
            -Parameters $PSBoundParameters
        Add-M365DSCTelemetryEvent -Data $data
        #endregion

        $nullResult = $PSBoundParameters
        $nullResult.Ensure = 'Absent'

        $getValue = $null
        #region resource generator code
        if ($id -ne $null) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors?`$select=id,lastHeartbeatDateTime,partnerState,androidEnabled,iosEnabled,windowsEnabled,macEnabled,androidMobileApplicationManagementEnabled,iosMobileApplicationManagementEnabled,windowsMobileApplicationManagementEnabled"
            $getValue = Invoke-MgGraphRequest -Uri $uri -Method GET
        }

        if ($null -eq $getValue.value) {
            Write-Verbose -Message "Could not find an Defender connector"
            return $nullResult
        }
        #endregion
        if ($null -eq $getValue.value) {
            Write-Verbose -Message "Could not find an Intune Policy Sets with DisplayName {$DisplayName}"
            return $nullResult
        }
        $Id = $getValue.Id
        Write-Verbose -Message "An Intune Policy Sets with Id {$Id} and DisplayName {$DisplayName} was found."

        $results = @{
            #region resource generator code
            Id                                        = $getValue.value.id
            LastHeartbeatDateTime                     = $getValue.value.lastHeartbeatDateTime
            PartnerState                              = $getValue.value.partnerState
            WindowsEnabled                            = $getValue.value.windowsEnabled
            TenantId                                  = $TenantId
            AndroidEnabled                            = $getValue.value.androidEnabled
            WindowsMobileApplicationManagementEnabled = $getValue.value.windowsMobileApplicationManagementEnabled
            AndroidMobileApplicationManagementEnabled = $getValue.value.androidMobileApplicationManagementEnabled
            IosEnabled                                = $getValue.value.iosEnabled
            MacEnabled                                = $getValue.value.macEnabled
            IosMobileApplicationManagementEnabled     = $getValue.value.iosMobileApplicationManagementEnabled
            #endregion
        }

        if ($getValue.GuidedDeploymentTags -eq $null) {
            $results.GuidedDeploymentTags = @()
        }
        return [System.Collections.Hashtable] $results
    }
    catch {
        New-M365DSCLogEntry -Message 'Error retrieving data:' `
            -Exception $_ `
            -Source $($MyInvocation.MyCommand.Source) `
            -TenantId $TenantId `
            -Credential $Credential

        return $nullResult
    }
}

function Set-TargetResource {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity,

        [Parameter()]
        [System.String[]]
        $AccessTokens

    )
    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
    $CommandName = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    $currentInstance = Get-TargetResource @PSBoundParameters

    $BoundParameters = Remove-M365DSCAuthenticationParameter -BoundParameters $PSBoundParameters

    if ($Ensure -eq 'Present' -and $currentInstance.Ensure -eq 'Absent') {
        Write-Verbose -Message "Creating an Intune Policy Sets with DisplayName {$DisplayName}"
        # remove complex values
        $BoundParameters.Remove("Assignments") | Out-Null
        $BoundParameters.Remove("Items") | Out-Null
        # remove unused values
        $BoundParameters.Remove('Id') | Out-Null

        $CreateParameters = ([Hashtable]$BoundParameters).clone()
        $CreateParameters = Rename-M365DSCCimInstanceParameter -Properties $CreateParameters

        $keys = (([Hashtable]$CreateParameters).clone()).Keys
        foreach ($key in $keys) {
            if ($null -ne $CreateParameters.$key -and $CreateParameters.$key.getType().Name -like '*cimInstance*') {
                $CreateParameters.$key = Convert-M365DSCDRGComplexTypeToHashtable -ComplexObject $CreateParameters.$key
            }
        }

        # set assignments and items to work with New-MgbetaDeviceAppManagementPolicySet command
        $assignmentsHash = ConvertTo-IntunePolicyAssignment -IncludeDeviceFilter:$true -Assignments $Assignments
        $CreateParameters.Add("Assignments", $assignmentsHash)

        $itemsHash = @()
        foreach ($item in $items) {
            $itemsHash += @{
                PayloadId            = $item.payloadId
                "@odata.type"        = $item.dataType
                guidedDeploymentTags = $item.guidedDeploymentTags
            }
        }
        $CreateParameters.Add("Items", $itemsHash)

        write-verbose -Message ($CreateParameters | out-string)
        $policy = New-MgbetaDeviceAppManagementPolicySet @CreateParameters

    }
    elseif ($Ensure -eq 'Present' -and $currentInstance.Ensure -eq 'Present') {
        Write-Verbose -Message "Updating the Intune Policy Sets with Id {$($currentInstance.Id)}"
        # remove complex values
        $BoundParameters.Remove("Assignments") | Out-Null
        $BoundParameters.Remove("Items") | Out-Null
        # remove unused values
        $BoundParameters.Remove('Id') | Out-Null

        $UpdateParameters = ([Hashtable]$BoundParameters).clone()
        $UpdateParameters = Rename-M365DSCCimInstanceParameter -Properties $UpdateParameters

        $keys = (([Hashtable]$UpdateParameters).clone()).Keys
        foreach ($key in $keys) {
            if ($null -ne $UpdateParameters.$key -and $UpdateParameters.$key.getType().Name -like '*cimInstance*') {
                $UpdateParameters.$key = Convert-M365DSCDRGComplexTypeToHashtable -ComplexObject $UpdateParameters.$key
            }
        }
        #region resource generator code
        $UpdateParameters.Add("PolicySetId", $currentInstance.Id)

        Update-MgbetaDeviceAppManagementPolicySet  @UpdateParameters

        if ($null -ne ($itemamendments = Get-ItemsAmendmentsObject -currentObjectItems $currentInstance.Items -targetObjectItems $items)) {
            $url = ('https://graph.microsoft.com/beta/deviceAppManagement/policySets/' + $currentInstance.Id + '/update' )
            Invoke-MgGraphRequest -Method POST -Uri $url -Body $itemamendments
        }

        $assignmentsHash = ConvertTo-IntunePolicyAssignment -IncludeDeviceFilter:$true -Assignments $Assignments
        $url = ('https://graph.microsoft.com/beta/deviceAppManagement/policySets/' + $currentInstance.Id + '/update' )
        Invoke-MgGraphRequest -Method POST -Uri $url -Body $assignmentsHash
        #endregion
    }
    elseif ($Ensure -eq 'Absent' -and $currentInstance.Ensure -eq 'Present') {
        Write-Verbose -Message "Removing the Intune Policy Sets with Id {$($currentInstance.Id)}"
        #region resource generator code
        Remove-MgbetaDeviceAppManagementPolicySet -PolicySetId $currentInstance.Id
        #endregion
    }
}

function Test-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
                [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity,

        [Parameter()]
        [System.String[]]
        $AccessTokens
    )

    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
    $CommandName = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    Write-Verbose -Message "Testing configuration of the Intune Policy Sets with Id {$Id} and DisplayName {$DisplayName}"

    $CurrentValues = Get-TargetResource @PSBoundParameters
    $ValuesToCheck = ([Hashtable]$PSBoundParameters).clone()

    if ($CurrentValues.Ensure -ne $Ensure) {
        Write-Verbose -Message "Test-TargetResource returned $false"
        return $false
    }
    $testResult = $true

    #Compare Cim instances
    foreach ($key in $PSBoundParameters.Keys) {
        $source = $PSBoundParameters.$key
        $target = $CurrentValues.$key
        if ($source.getType().Name -like '*CimInstance*') {
            $testResult = Compare-M365DSCComplexObject `
                -Source ($source) `
                -Target ($target)

            if (-Not $testResult) {
                $testResult = $false
                break
            }

            $ValuesToCheck.Remove($key) | Out-Null
        }
    }

    $ValuesToCheck.remove('Id') | Out-Null

    Write-Verbose -Message "Current Values: $(Convert-M365DscHashtableToString -Hashtable $CurrentValues)"
    Write-Verbose -Message "Target Values: $(Convert-M365DscHashtableToString -Hashtable $ValuesToCheck)"

    if ($testResult) {
        $testResult = Test-M365DSCParameterState -CurrentValues $CurrentValues `
            -Source $($MyInvocation.MyCommand.Source) `
            -DesiredValues $PSBoundParameters `
            -ValuesToCheck $ValuesToCheck.Keys
    }

    Write-Verbose -Message "Test-TargetResource returned $testResult"

    return $testResult
}

function Export-TargetResource {
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity,

        [Parameter()]
        [System.String[]]
        $AccessTokens
    )

    $ConnectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
        -InboundParameters $PSBoundParameters

    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
    $CommandName = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    try {
        $getValue = $null
        #region resource generator code
        if ($id -ne $null) {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors?`$select=id,lastHeartbeatDateTime,partnerState,androidEnabled,iosEnabled,windowsEnabled,macEnabled,androidMobileApplicationManagementEnabled,iosMobileApplicationManagementEnabled,windowsMobileApplicationManagementEnabled"
            $getValue = (Invoke-MgGraphRequest -Uri $uri -Method GET).value
        }

        $i = 1
        $dscContent = ''
        if ($getValue.Length -eq 0) {
            Write-Host $Global:M365DSCEmojiGreenCheckMark
        }
        else {
            Write-Host "`r`n" -NoNewline
        }
        foreach ($config in $getValue) {
            if ($null -ne $Global:M365DSCExportResourceInstancesCount) {
                $Global:M365DSCExportResourceInstancesCount++
            }

            $displayedKey = $config.Id
            if (-not [String]::IsNullOrEmpty($config.displayName)) {
                $displayedKey = $config.displayName
            }
            Write-Host "    |---[$i/$($getValue.Count)] $displayedKey" -NoNewline
            $params = @{
                Id                    = $config.Id
                DisplayName           = $config.DisplayName
                Ensure                = 'Present'
                Credential            = $Credential
                ApplicationId         = $ApplicationId
                TenantId              = $TenantId
                ApplicationSecret     = $ApplicationSecret
                CertificateThumbprint = $CertificateThumbprint
                Managedidentity       = $ManagedIdentity.IsPresent
                AccessTokens          = $AccessTokens
            }

            $Results = Get-TargetResource @Params
            $Results = Update-M365DSCExportAuthenticationResults -ConnectionMode $ConnectionMode `
                -Results $Results
            if ($Results.Assignments) {
                $complexTypeStringResult = Get-M365DSCDRGComplexTypeToString -ComplexObject $Results.Assignments -CIMInstanceName DeviceManagementConfigurationPolicyAssignments
                if ($complexTypeStringResult) {
                    $Results.Assignments = $complexTypeStringResult
                }
                else {
                    $Results.Remove('Assignments') | Out-Null
                }
            }
            if ($Results.Items) {
                $complexTypeStringResult = Get-M365DSCDRGComplexTypeToString -ComplexObject $Results.Items -CIMInstanceName DeviceManagementConfigurationPolicyItems
                if ($complexTypeStringResult) {
                    $Results.Items = $complexTypeStringResult
                }
                else {
                    $Results.Remove('Items') | Out-Null
                }
            }
            $currentDSCBlock = Get-M365DSCExportContentForResource -ResourceName $ResourceName `
                -ConnectionMode $ConnectionMode `
                -ModulePath $PSScriptRoot `
                -Results $Results `
                -Credential $Credential
            if ($Results.Assignments) {
                $currentDSCBlock = Convert-DSCStringParamToVariable -DSCBlock $currentDSCBlock -ParameterName "Assignments" -isCIMArray:$true
            }
            if ($Results.Items) {
                $currentDSCBlock = Convert-DSCStringParamToVariable -DSCBlock $currentDSCBlock -ParameterName "Items" -isCIMArray:$true
            }

            $dscContent += $currentDSCBlock
            Save-M365DSCPartialExport -Content $currentDSCBlock `
                -FileName $Global:PartialExportFileName
            $i++
            Write-Host $Global:M365DSCEmojiGreenCheckMark
        }
        return $dscContent
    }
    catch {
        if ($_.Exception -like "*401*" -or $_.ErrorDetails.Message -like "*`"ErrorCode`":`"Forbidden`"*" -or
            $_.Exception -like "* Unauthorized*" -or `
                $_.Exception -like "*Request not applicable to target tenant*") {
            Write-Host "`r`n    $($Global:M365DSCEmojiYellowCircle) The current tenant is not registered for Intune."
        }
        else {
            Write-Host $Global:M365DSCEmojiRedX

            New-M365DSCLogEntry -Message 'Error during Export:' `
                -Exception $_ `
                -Source $($MyInvocation.MyCommand.Source) `
                -TenantId $TenantId `
                -Credential $Credential
        }

        return ''
    }
}

function Get-ItemsAmendmentsObject {
    param (
        $currentObjectItems,
        $targetObjectItems
    )

    $nullreturn = $true
    $ItemsModificationTemplate = @{
        deletedPolicySetItems = @()
        updatedPolicySetItems = @()
        addedPolicySetItems   = @()
    }

    $currentObjectItems | foreach {

        if (!($targetObjectItems.Payloadid -contains $_.PayloadId)) {
            write-verbose -message ($_.DisplayName + ' NOT present in Config Document, Removing')
            $ItemsModificationTemplate.deletedPolicySetItems += $_.Id
            $nullreturn = $false
        }

    }

    $targetObjectItems | foreach {

        if (!($currentObjectItems.PayloadId -contains $_.PayloadId)) {
            write-verbose -message ($_.DisplayName + ' NOT already present in Policy Set, Adding')
            $ItemsModificationTemplate.addedPolicySetItems += @{
                payloadId            = $_.payloadId
                "@odata.type"        = $_.dataType
                guidedDeploymentTags = $_.guidedDeploymentTags
            }
            $nullreturn = $false
        }

    }

    if (!$nullreturn) {
        return $ItemsModificationTemplate
    }

    return $null

}

Export-ModuleMember -Function *-TargetResource
