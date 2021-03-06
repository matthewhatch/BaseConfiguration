<#
    Summary
    =======
    This custom resource is used to grant or revoke a privilege to an identity.
	
    This resource requries that the "Carbon" module be pre-installed
    on the server. (http://get-carbon.org).
 
    Revision History
    ================
    6/9/2014 - Initial Version
               (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        ValueMatch = (VALUE MATCH) Privilege found with matching value - Identity: '{0}', Privilege: '{1}', Value: '{2}'
        ValueMisMatch = (VALUE MISMATCH) Privilege found with mismatching value - Identity: '{0}', Privilege: '{1}', with Value: '{2}' mismatched the specified Value: '{3}'        
        ValueSet = (SET) Privilege set - Identity: '{0}', Privilege: '{1}', Value: '{2}'        
'@
}

Import-Module Carbon

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
		$Identity,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Privilege,

		[Boolean]
		$Value
	)

    # Check if Carbon module is present
    if(!(Get-Module -ListAvailable -Name Carbon))
    {
        Throw "Please ensure that Carbon module is installed."
    }
    
	$results = Test-Privilege -Identity $Identity -Privilege $Privilege
    return @{Identity=$Identity; Privilege=$Privilege; Value=$results}      
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
		$Identity,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Privilege,

		[boolean]
		$Value = $true
	)

    # Check if Carbon module is present
    if(!(Get-Module -ListAvailable -Name Carbon))
    {
        Throw "Please ensure that Carbon module is installed."
    }

    $results = Test-Privilege -Identity $Identity -Privilege $Privilege
    if ($Value -eq $results)
    {
        Write-Verbose ($localizedData.ValueMatch -f $Identity, $Privilege, $Value)
    }
    else
    {
        Write-Verbose ($localizedData.ValueMisMatch -f $Identity, $Privilege, $results, $Value)

        $successMessage = $localizedData.ValueSet -f $Identity, $Privilege, $Value
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
			if ($value)
			{
				Grant-Privilege -Identity $Identity -Privilege $Privilege
			}
			else
			{
				Revoke-Privilege -Identity $Identity -Privilege $Privilege
			}
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
		$Identity,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Privilege,

		[boolean]
        $Value = $true
	)
 
    # Check if Carbon module is present
    if(!(Get-Module -ListAvailable -Name Carbon))
    {
        Throw "Please ensure that Carbon module is installed."
    }

    $results = Test-Privilege -Identity $Identity -Privilege $Privilege
    if ($Value -eq $results)
    {
        Write-Verbose ($localizedData.ValueMatch -f $Identity, $Privilege, $Value)
        return $true                
    }
    else
    {
        Write-Verbose ($localizedData.ValueMisMatch -f $Identity, $Privilege, $results, $Value)
        return $false
    }
}

Export-ModuleMember -Function *-TargetResource



