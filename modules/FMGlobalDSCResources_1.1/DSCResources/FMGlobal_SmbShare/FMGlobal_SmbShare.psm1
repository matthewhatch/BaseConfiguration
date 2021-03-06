<#
    Summary
    =======
    This custom resource is used to create SmbShares. It was
    created because the xSmbShare resource contained in the
    Resource kit from Microsoft only works on WS2012.

    Revision History
    ================
    6/5/2014 - Initial Version
               (Jeff Pflum)
#>

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'        
        ShareNotFound = (NOT FOUND) Share not found - Name: '{0}'
        ShareFound = (FOUND) Share found - Name: '{0}'
        ShareFoundWithCorrectPath = (FOUND CORRECT PATH) Share found with correct path - Name: '{0}', Path: '{1}'
        ShareFoundWithIncorrectPath = (FOUND INCORRECT PATH) Share found with incorrect path - Name: '{0}', with Path: '{1}' mismatched the specified Path: '{2}'        
        ShareCreated = (CREATED) Share - Name: '{0}', Path: '{1}', Remark: '{2}', Grant: '{3}'        
        ShouldCreateShare = (SHOULD CREATE) Should create share? - Name: '{0}', Path: '{1}', Remark: '{2}', Grant: '{3}'        
        ShareCreateError = (ERROR) Error creating share - Name: '{0}', Path: '{1}', ExitCode: '{2}'
        ShareDeleted = (DELETED) Existing share deleted - Name: '{0}', Path: '{1}'
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
		$Name
	)

	$Path = ""
	$Remark = ""
	$Grant = $null

    $Share = Get-CimInstance -ClassName Win32_Share -Filter "Name = '$Name'"
    if ($Share)
    {
        Write-Verbose ($localizedData.ShareFound -f $Name)
        $Path = $Share.Path
        $Remark = $Share.Description
    }
    else
    {
        Write-Verbose ($localizedData.ShareNotFound -f $Name)
    }

    return @{Name=$Name; Path=$Path; Remark=$Remark; Grant=$Grant}
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
		$Name,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Path,

		[System.String]
		$Remark,

		[System.String[]]
		$Grant
	)

    $Share = Get-CimInstance -ClassName Win32_Share -Filter "Name = '$Name'"
    if ($Share)
    {
        if ($Share.Path -eq $path)
        {
            Write-Verbose ($localizedData.ShareFoundWithCorrectPath -f $Name, $Path)
            return
        }
        else
        {
            Write-Verbose ($localizedData.ShareFoundWithIncorrectPath -f $Name, $Share.Path, $Path)
        }
    }
    else
    {
        Write-Verbose ($localizedData.ShareNotFound -f $Name)
    }
    
    $GrantAsString = ""
    if ($Grant)
    {
        $GrantAsString = [System.String]::Join(";", $Grant)
    }

    $shouldProcessMessage = $localizedData.ShouldCreateShare -f $Name, $Path, $Remark, $GrantAsString
    if ($PSCmdlet.ShouldProcess($shouldProcessMessage, $null, $null))
    {
        # Delete the existing share if it exists because if we are here its path isn't correct
        if ($Share)
        {
            Remove-CimInstance -InputObject $Share
            Write-Verbose ($localizedData.ShareDeleted -f $Name, $Share.Path)
        }

        # Create the share
        $grants = ""
        if ($Grant)
        {
            foreach ($perm in $Grant)
            {
                $grants = $grants + " ""/GRANT:" + $perm + """"
            }
        }

        $param = $Name + "=""" + $Path + """ /REMARK:""" + $Remark + """" + $grants
        $command = "net share " + $param
        Invoke-Expression "$command" -ErrorAction Ignore -WarningAction Ignore 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0)
        {
            Write-Verbose ($localizedData.ShareCreated -f $Name, $Path, $Remark, $GrantAsString)
        }
        else
        {
            Write-Verbose ($localizedData.ShareCreateError -f $Name, $Path, $LASTEXITCODE)
        }
    }

	return
}

#-------------------------------
# The Test-TargetResource cmdlet
#-------------------------------
<#
    Function returns true if the share exists and is associated
    with the correct path. It returns false if the share doesn't
    exist or if it does but is associated with a different
    path. It does not validate permissions specified via the
    Grant parameter.
#>
function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Path,

		[System.String]
		$Remark,

		[System.String[]]
		$Grant
	)

    $Share = Get-CimInstance -ClassName Win32_Share -Filter "Name = '$Name'"
    if ($Share)
    {
        if ($Share.Path -eq $path)
        {
            Write-Verbose ($localizedData.ShareFoundWithCorrectPath -f $Name, $Path)
            return $true
        }

        Write-Verbose ($localizedData.ShareFoundWithIncorrectPath -f $Name, $Share.Path, $Path)
        return $false
    }
    else
    {
        Write-Verbose ($localizedData.ShareNotFound -f $Name)
    }

	return $false 
}

Export-ModuleMember -Function *-TargetResource



