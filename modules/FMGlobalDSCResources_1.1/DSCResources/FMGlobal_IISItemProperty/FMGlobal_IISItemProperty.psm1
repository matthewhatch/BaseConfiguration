<#
    Summary
    =======
    This custom resource is used to get and set IIS specific item properties.
    It uses the Get-ItemProperty and Set-ItemProperty
    cmdlets with IIS PowerShell Drive provided in the WebAdministration
	module provided with IIS7.5.

    Revision History
    ================
    5/30/2014 - Initial Version
               (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        PropertyNotFound = (NOT FOUND) Item property not found - Path: '{0}, Name: '{1}'
        PropertyFound = (FOUND) Item property found - Path: '{0}', Name: '{1}', Value: '{2}'
        PropertyFoundWithMisMatchingValue = (FOUND MISMATCH) Item property found with mismatching value - Path: '{0}', Name: '{1}', with Value: '{2}' mismatched the specified Value: '{3}'        
        PropertyUnchanged = (UNCHANGED) Item property - Path: '{0}', Name: '{1}', Value '{2}'
        PropertySet = (SET) Item property - Path: '{0}', Name: '{1}', Value: '{2}'        
        PropertySetError = (ERROR) Failed to set item property - Path: '{0}', Name: '{1}', Value: '{2}'
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
		$Path,

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

    $itemProperty = Get-ItemProperty -Path $Path -Name $Name
    if ($itemProperty -eq $null)
    {        
        Write-Verbose ($localizedData.PropertyNotFound -f $Path, $Name)
        return @{Path=$Path; Name=$Name}      
    }   

    Write-Verbose ($localizedData.PropertyFound -f $Path, $Name, $itemProperty)
    return @{Path=$Path; Name=$Name; Value=$itemProperty}
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
		$Path,

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

    $itemProperty = Get-ItemProperty -Path $Path -Name $Name
    if ($itemProperty -eq $null)
    {        
        Write-Verbose ($localizedData.PropertyNotFound -f $Path, $Name)
            
        $successMessage = $localizedData.PropertySet -f $Path, $Name, $Value
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -WarningVariable warn
            if ($warn)
            {
                Write-Verbose ($localizedData.PropertySetError -f $Path, $Name, $Value)
                throw $warn
            }
            Write-Verbose ($successMessage)
        }
        return
    }

    if ($Value -eq $itemProperty)
    {
        Write-Verbose ($localizedData.PropertyUnchanged -f $Path, $Name, $itemProperty)
    }
    else
    {
        Write-Verbose ($localizedData.PropertyFoundWithMisMatchingValue -f $Path, $Name, $itemProperty, $Value)

        $successMessage = $localizedData.PropertySet -f $Path, $Name, $Value
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -WarningVariable warn
            if ($warn)
            {
                Write-Verbose ($localizedData.PropertySetError -f $Path, $Name, $Value)
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
		$Path,

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

    $itemProperty = Get-ItemProperty -Path $Path -Name $Name
    if ($itemProperty -eq $null)
    {        
        Write-Verbose ($localizedData.PropertyNotFound -f $Path, $Name)
        return $false
    }

    if ($Value -eq $itemProperty)
    {
        Write-Verbose ($localizedData.PropertyFound -f $Path, $Name, $itemProperty)
        return $true                
    }
    else
    {
        Write-Verbose ($localizedData.PropertyFoundWithMisMatchingValue -f $Path, $Name, $itemProperty, $Value)
        return $false
    }
}

Export-ModuleMember -Function *-TargetResource



