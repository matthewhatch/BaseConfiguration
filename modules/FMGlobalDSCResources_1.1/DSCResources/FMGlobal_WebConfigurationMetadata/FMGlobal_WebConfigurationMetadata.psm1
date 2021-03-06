<#
    Summary
    =======
    This custom resource is used to get and set IIS configuration element metadata.
    It uses the Get-WebConfiguration and Set-WebConfiguration
    cmdlets contained in the WebAdministration module provide for IIS7.5.

    Revision History
    ================
    5/21/2014 - Initial Version
               (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        ConfigElementMetadataNotFound = (NOT FOUND) Configuration element metadata not found - Filter: '{0}, PSPath: '{1}', Metadata: '{2}'
        ConfigElementMetadataFound = (FOUND) Configuration element metadata found - Filter: '{0}', PSPath: '{1}', Metadata: '{2}', Value: '{3}'       
		ConfigElementMetadataFoundWithMisMatchingValue = (FOUND MISMATCH) Configuration element metadata found with mismatching value - Filter: '{0}', PSPath: '{1}', Metadata: '{2}'with Value: '{3}' mismatched the specified Value: '{4}'        
        ConfigElementMetadataUnchanged = (UNCHANGED) Configuration element metadata unchanged - Filter: '{0}', PSPath: '{1}', Metadata: '{2}', Value '{3}'
        ConfigElementMetadataSet = (SET) Configuration element metadata set - Filter: '{0}', PSPath: '{1}', Metadata: '{2}', Old Value '{3}', New Value: '{4}'        
        ConfigElementMetadataSetError = (ERROR) Failed to set configuration element metadata - Filter: '{0}', PSPath: '{1}', Metadata: '{2}', Value: '{3}'
'@
}

Import-Module WebAdministration

#------------------------------
# The Get-TargetResource cmdlet
#------------------------------
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Filter,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$PSPath,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Metadata
	)

    # Check if WebAdministration module is present for IIS cmdlets
    if(!(Get-Module -ListAvailable -Name WebAdministration))
    {
        Throw "Please ensure that WebAdministration module is installed."
    }

    $configElement = Get-WebConfiguration -Filter $Filter -PSPath $PSPath -Metadata
    if($configElement -eq $null)
    {        
        Write-Verbose ($localizedData.ConfigElementMetadataNotFound -f $Filter, $PSPath, $Metadata)
        return @{Filter=$Filter; PSPath=$PSPath; Metadata=$Metadata}      
    }   
   
    $configElementMetadataValue = $configElement.metadata.$Metadata
	if ($configElementMetadataValue -eq $null)
	{
        Write-Verbose ($localizedData.ConfigElementMetadataNotFound -f $Filter, $PSPath, $Metadata)     
        return @{Filter=$Filter; PSPath=$PSPath; Metadata=$Metadata}      
	}

    Write-Verbose ($localizedData.ConfigElementMetadataFound -f $Filter, $PSPath, $Metadata, $configElementValue)
    return @{Filter=$Filter; PSPath=$PSPath; Metadata=$Metadata; Value=$configElementMetadataValue}
}


#------------------------------
# The Set-TargetResource cmdlet
#------------------------------
function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess=$true)]
	param
	(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Filter,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$PSPath,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Metadata,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Value
	)

    # Check if WebAdministration module is present for IIS cmdlets
    if(!(Get-Module -ListAvailable -Name WebAdministration))
    {
        Throw "Please ensure that WebAdministration module is installed."
    }

    $configElement = Get-WebConfiguration -Filter $Filter -PSPath $PSPath -Metadata
    if ($configElement -eq $null)
    {   
		$errorMessage = $localizedData.ConfigElementMetdataNotFound -f $Filter, $PSPath, $Metadata     
        Write-Verbose ($errorMessage)
		throw $errorMessage
    }

    $configElementMetadataValue = $configElement.metadata.$Metadata
	if ($configElementMetadataValue -eq $null)
	{
		$errorMessage = $localizedData.ConfigElementMetdataNotFound -f $Filter, $PSPath, $Metadata     
        Write-Verbose ($errorMessage)
		throw $errorMessage
	}

    if ($Value -eq $configElementMetadataValue)
    {
		Write-Verbose ($localizedData.ConfigElementMetadataUnchanged -f $Filter, $PSPath, $Metadata, $configElementMetadataValue)               
    }
    else
    {
        Write-Verbose ($localizedData.ConfigElementMetadataFoundWithMisMatchingValue -f $Filter, $PSPath, $Metadata, $configElementMetadataValue, $Value)
        $successMessage = $localizedData.ConfigElementMetadataSet -f $Filter, $PSPath, $Metadata, $configElementMetadataValue, $Value
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
            Set-WebConfiguration -Filter $Filter -PSPath $PSPath -Metadata $Metadata -Value $Value -WarningVariable warn
            if ($warn)
            {
                Write-Verbose ($localizedData.ConfigElementMetadataSetError -f $Filter, $PSPath, $Metadata, $Value)
                throw $warn
            }
            Write-Verbose ($successMessage)
        }
    }
}

#-------------------------------
# The Test-TargetResource cmdlet
#-------------------------------
function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Filter,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$PSPath,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Metadata,

		[parameter(Mandatory = $true)]
		[System.String]
		$Value
	)
 
    # Check if WebAdministration module is present for IIS cmdlets
    if(!(Get-Module -ListAvailable -Name WebAdministration))
    {
        Throw "Please ensure that WebAdministration module is installed."
    }

    $configElement = Get-WebConfiguration -Filter $Filter -PSPath $PSPath -MetaData
    if($configElement -eq $null)
    {        
        Write-Verbose ($localizedData.ConfigElementMetadataNotFound -f $Filter, $PSPath, $Metadata)     
        return $false   
    }   

    $configElementMetadataValue = $configElement.metadata.$Metadata
	if ($configElementMetadataValue -eq $null)
	{
        Write-Verbose ($localizedData.ConfigElementMetadataNotFound -f $Filter, $PSPath, $Metadata)     
        return $false   
	}

    if ($Value -eq $configElementMetadataValue)
    {
		Write-Verbose ($localizedData.ConfigElementMetadataFound -f $Filter, $PSPath, $Metadata, $configElementMetadataValue)               
        return $true                
    }
    else
    {
        Write-Verbose ($localizedData.ConfigElementMetadataFoundWithMisMatchingValue -f $Filter, $PSPath, $Metadata, $configElementMetadataValue, $Value)
        return $false
    }
}

Export-ModuleMember -Function *-TargetResource



