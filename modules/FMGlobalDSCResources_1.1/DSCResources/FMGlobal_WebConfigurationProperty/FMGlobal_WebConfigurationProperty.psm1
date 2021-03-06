<#
    Summary
    =======
    This custom resource is used to get and set web configuration properties.
    It uses the Get-WebConfigurationProperty and Set-WebConfigurationProperty
    cmdlets contained in the WebAdministration module provide for IIS7.5.

    Revision History
    ================
    5/6/2014 - Initial Version
               (Jeff Pflum)
    11/10/2014 - Updated to correct problem setting properities with
                 various data types other than strings.
                 (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        PropertyNotFound = (NOT FOUND) Configuration property not found - Filter: '{0}, Name: '{1}'
        PropertyFound = (FOUND) Configuration property found - Filter: '{0}', Name: '{1}', Value: '{2}'
        PropertyFoundWithMisMatchingValue = (FOUND MISMATCH) Configuration property found with mismatching value - Filter: '{0}', Name: '{1}', with Value: '{2}' mismatched the specified Value: '{3}'        
        PropertyUnchanged = (UNCHANGED) Configuration property - Filter: '{0}', Name: '{1}', Value '{2}'
        PropertySet = (SET) Configuration property - Filter: '{0}', Name: '{1}', Value: '{2}'        
        PropertySetError = (ERROR) Failed to set configuration property - Filter: '{0}', Name: '{1}', Value: '{2}'
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
		$Name
	)

    # Check if WebAdministration module is present for IIS cmdlets
    if(!(Get-Module -ListAvailable -Name WebAdministration))
    {
        Throw "Please ensure that WebAdministration module is installed."
    }

    $configProperty = Get-WebConfigurationProperty -Filter $Filter -Name $Name
    if ($configProperty -eq $null)
    {        
        Write-Verbose ($localizedData.PropertyNotFound -f $Filter, $Name)
        return @{Filter=$Filter; Name=$Name}      
    }   

    # It appears that the cmdlet can return configuration properties
    # as one of two type: String or ConfigurationAttribute. As such
    # to get its value, we need to access it properly
    if ($configProperty.GetType().Name -eq "String")
    {
        $configPropertyValue = $configProperty
    }
    else
    {
        #Assumes $configProperty.GetType().Name -eq "ConfigurationAttribute"
        $configPropertyValue = $configProperty.Value
    }

    Write-Verbose ($localizedData.PropertyFound -f $Filter, $Name, $configPropertyValue)
    return @{Filter=$Filter; Name=$Name; Value=$configPropertyValue}
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
		$Name,

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

    $configProperty = Get-WebConfigurationProperty -Filter $Filter -Name $Name
    if ($configProperty -eq $null)
    {        
        Write-Verbose ($localizedData.PropertyNotFound -f $Filter, $Name)
            
        $successMessage = $localizedData.PropertySet -f $Filter, $Name, $Value
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
            if ($configProperty.GetType().Name -eq "String")
            {
                $NewValue = $Value
            }
            elseif ($configProperty.TypeName -eq "System.Boolean")
            {
                $NewValue = [System.Convert]::ToBoolean($Value)
            }
            else
            {
                $NewValue = $Value -as $configProperty.TypeName
            }

            Set-WebConfigurationProperty -Filter $Filter -Name $Name -Value $NewValue -WarningVariable warn
            if ($warn)
            {
                Write-Verbose ($localizedData.PropertySetError -f $Filter, $Name, $Value)
                throw $warn
            }
            Write-Verbose ($successMessage)
        }
        return
    }

    # It appears that the cmdlet can return configuration properties
    # as one of two type: String or ConfigurationAttribute. As such
    # to get its value, we need to access it properly
    if ($configProperty.GetType().Name -eq "String")
    {
        $configPropertyValue = $configProperty
    }
    else
    {
        #Assumes $configProperty.GetType().Name -eq "ConfigurationAttribute"
        $configPropertyValue = $configProperty.Value
    }

    if ($Value -eq $configPropertyValue)
    {
        Write-Verbose ($localizedData.PropertyUnchanged -f $Filter, $Name, $configPropertyValue)
    }
    else
    {
        Write-Verbose ($localizedData.PropertyFoundWithMisMatchingValue -f $Filter, $Name, $configPropertyValue, $Value)

        $successMessage = $localizedData.PropertySet -f $Filter, $Name, $Value
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
            if ($configProperty.GetType().Name -eq "String")
            {
                $NewValue = $Value
            }
            elseif ($configProperty.TypeName -eq "System.Boolean")
            {
                $NewValue = [System.Convert]::ToBoolean($Value)
            }
            else
            {
                $NewValue = $Value -as $configProperty.TypeName
            }

            Set-WebConfigurationProperty -Filter $Filter -Name $Name -Value $NewValue -WarningVariable warn
            if ($warn)
            {
                Write-Verbose ($localizedData.PropertySetError -f $Filter, $Name, $Value)
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
		$Name,

		[parameter(Mandatory = $true)]
		[System.String]
		$Value
	)
 
    # Check if WebAdministration module is present for IIS cmdlets
    if(!(Get-Module -ListAvailable -Name WebAdministration))
    {
        Throw "Please ensure that WebAdministration module is installed."
    }

    $configProperty = Get-WebConfigurationProperty -Filter $Filter -Name $Name
    if ($configProperty -eq $null)
    {        
        Write-Verbose ($localizedData.PropertyNotFound -f $Filter, $Name)
        return $false
    }

    # It appears that the cmdlet can return configuration properties
    # as one of two type: String or ConfigurationAttribute. As such
    # to get its value, we need to access it properly
    if ($configProperty.GetType().Name -eq "String")
    {
        $configPropertyValue = $configProperty
    }
    else
    {
        #Assumes $configProperty.GetType().Name -eq "ConfigurationAttribute"
        $configPropertyValue = $configProperty.Value
    }

    if ($Value -eq $configPropertyValue)
    {
        Write-Verbose ($localizedData.PropertyFound -f $Filter, $Name, $configPropertyValue)
        return $true                
    }
    else
    {
        Write-Verbose ($localizedData.PropertyFoundWithMisMatchingValue -f $Filter, $Name, $configPropertyValue, $Value)
        return $false
    }
}

Export-ModuleMember -Function *-TargetResource



