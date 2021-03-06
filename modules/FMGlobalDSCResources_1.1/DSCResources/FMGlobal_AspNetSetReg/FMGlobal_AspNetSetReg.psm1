<#
    Summary
    =======
    This custom resource is used encrypt a username and password
    in the registry using the aspnet_setreg utility.

    Revision History
    ================
    6/12/2014 - Initial Version
                (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        SubkeyExists = (SUBKEY EXISTS) Subkey: '{0}'
        SubkeyDoesNotExist = (SUBKEY DOES NOT EXIST) Subkey: '{0}'
        SubkeyCreated = (SUBKEY CREATED) Subkey: '{0}'
        ShouldCreateSubkey = (SHOULD CREATE SUBKEY) Subkey: '{0}' 
        SubkeyCreateError = (ERROR CREATING SUBKEY) Subkey: '{0}', ExitCode: '{1}'
'@
}

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
		$HKLMSoftwareSubkey
	)

    $Path = "HKLM:\Software\Wow6432Node\" + $HKLMSoftwareSubkey + "\ASPNET_SETREG"
    $result = Test-Path -Path $Path

    return @{HKLMSoftwareSubkey=$HKLMSoftwareSubkey; Value=$result}      
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
		$HKLMSoftwareSubkey,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
	)

    $result = Test-TargetResource -HKLMSoftwareSubkey $HKLMSoftwareSubkey
    if (!$result)
    {
        $successMessage = $localizedData.ShouldCreateSubkey -f $HKLMSoftwareSubkey
        if ($PSCmdlet.ShouldProcess($successMessage, $null, $null))
        {
            $networkCredential = $Credential.GetNetworkCredential();
            $username = $networkCredential.Domain + "\" + $networkCredential.UserName
            $password = $networkCredential.Password
            $subkey = "Software\" + $HKLMSoftwareSubkey
            $command = $Env:SystemDrive + "\'Program Files (x86)'\aspnet_setreg\aspnet_setreg.exe -k:" + $subkey + " -u:" + $username + " -p:" + $password
			Invoke-Expression $command -ErrorVariable err -ErrorAction Ignore -WarningAction Ignore 2>&1 | Out-Null
            if (-not $err)
            {
                Write-Verbose ($localizedData.SubkeyCreated -f $HKLMSoftwareSubkey)
            }
            else
            {
                Write-Verbose ($localizedData.SubkeyCreateError -f $HKLMSoftwareSubkey, $err.Exception.ToString())
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
		$HKLMSoftwareSubkey,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
	)
 
    $Path = "HKLM:\Software\Wow6432Node\" + $HKLMSoftwareSubkey + "\ASPNET_SETREG"
    $result = Test-Path -Path $Path
    if ($result)
    {
        Write-Verbose ($localizedData.SubkeyExists -f $HKLMSoftwareSubkey)
        return $true                
    }
    else
    {
        Write-Verbose ($localizedData.SubkeyDoesNotExist -f $HKLMSoftwareSubkey)
        return $false
    }
}

Export-ModuleMember -Function *-TargetResource