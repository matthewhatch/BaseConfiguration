<#
    Summary
    =======
    This custom resource is used to Grant a permission on a 
    file, directory or registry key.

    This resource requries that the "Carbon" module be pre-installed
    on the server. (http://get-carbon.org).

    Revision History
    ================
    6/11/2014 - Initial Version
               (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        PermissionGranted = (PERMISSION GRANTED) Path: '{0}', Identity: '{1}', Permission: '{2}'
        PermissionAlreadyGranted = (PERMISSION ALREADY GRANTED) Path: '{0}', Identity: '{1}', Permission: '{2}'
        PermissionNotGranted = (PERMISSION NOT GRANTED) Path: '{0}', Identity: '{1}', Permission: '{2}'   
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
		$Path,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Identity,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String[]]
		$Permission
	)

    # Check if Carbon module is present
    if(!(Get-Module -ListAvailable -Name Carbon))
    {
        Throw "Please ensure that Carbon module is installed."
    }
    
    $result = Test-Permission -Path $Path -Identity $Identity -Permission $Permission -Inherited

    return @{Path=$Path; Identity=$Identity; Permission=[string]::Join(",", $Permission); Inherited=$Inherited; Value=$result}      
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
		$Identity,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String[]]
		$Permission
	)

    # Check if Carbon module is present
    if(!(Get-Module -ListAvailable -Name Carbon))
    {
        Throw "Please ensure that Carbon module is installed."
    }

    $result = Test-Permission -Path $Path -Identity $Identity -Permission $Permission -Inherited
    if ($result)
    {
        Write-Verbose ($localizedData.PermissionAlreadyGranted -f $Path, $Identity, $Permission)
    }
    else
    {
        Write-Verbose ($localizedData.PermissionNotGranted -f $Path, $Identity, [string]::Join(",", $Permission))

        $successMessage = $localizedData.PermissionGranted -f $Path, $Identity, [string]::Join(",", $Permission)
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
			Grant-Permission -Path $Path -Identity $Identity -Permission $Permission
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
		$Identity,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String[]]
		$Permission
	)
 
    # Check if Carbon module is present
    if(!(Get-Module -ListAvailable -Name Carbon))
    {
        Throw "Please ensure that Carbon module is installed."
    }

    $result = Test-Permission -Path $Path -Identity $Identity -Permission $Permission -Inherited
    if ($result)
    {
        Write-Verbose ($localizedData.PermissionGranted -f $Path, $Identity, [string]::Join(",", $Permission))
        return $true                
    }
    else
    {
        Write-Verbose ($localizedData.PermissionNotGranted -f $Path, $Identity, [string]::Join(",", $Permission))
        return $false
    }
}

Export-ModuleMember -Function *-TargetResource