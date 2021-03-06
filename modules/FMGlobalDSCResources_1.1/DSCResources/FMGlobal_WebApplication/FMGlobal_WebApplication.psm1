function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name
	)

	__checkDependencies
    Write-Verbose "Getting Web App $Name"
    $WebApp = Get-WebApplication -Name $Name

    if($WebApp.count -eq 1){
        $returnValue = @{
            Name = $Name
            PhysicalPath = $WebApp.PhysicalPath
            AppPool = $WebApp.ApplicationPool
        }
    }


    return $returnValue
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

        [System.String]
        $WebSite,

		[System.String]
		$PhysicalPath,

		[System.String]
		$AppPool
	)
    
    __checkDependencies
    $PSBoundParameters.Add("Set",$true)
    __testWebApp @PSBoundParameters

}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

        [System.String]
        $WebSite,

		[System.String]
		$PhysicalPath,

		[System.String]
		$AppPool
	)

	__checkDependencies
    $isDesiredState = __testWebApp @PSBoundParameters
    Write-Output $isDesiredState
}

function __checkDependencies
{
    Write-Verbose "Checking whether WebAdministration is there in the machine or not."
    # Check if WebAdministration module is present for IIS cmdlets
    if(!(Get-Module -ListAvailable -Name WebAdministration))
    {
        Throw "Please ensure that WebAdministration module is installed."
    }
}

function __testWebApp{
    param(
        [parameter(Mandatory = $true)]
		[System.String]
		$Name,

        [System.String]
        $WebSite,

		[System.String]
		$PhysicalPath,

		[System.String]
		$AppPool,

        [switch]
        $set
    )

    $WebApp = Get-WebApplication -Name $Name
    $isDesiredState = $true

    do{
        if($WebApp -eq $null){
            Write-Verbose "There is no Appliction with the name $Name"
            Write-Verbose "Since $Name is not installed, Desired State does not need to be checked"
            break
        }else{
            
            #check if Physical Path doesn't match
            if($PSBoundParameters.ContainsKey("PhysicalPath")){
                if($WebApp.PhysicalPath -ne $PhysicalPath){
                    if($set){
                        #update the WebappConfiguration
                        Write-Verbose "Updating the Physical Path to $PhysicalPath for App $Name Under Website $WebSite"
                        Set-ItemProperty -Path IIS:Sites\$Website\$Name -Name physicalPath -Value $PhysicalPath
                    }
                    else{
                        Write-Verbose "Physical Path Does not match Desired State"
                        $isDesiredState = $false
                        break
                    }
                }    
            }
            
            #check if the apppool doesn't match
            if($PSBoundParameters.ContainsKey("AppPool")){
                if($WebApp.ApplicationPool -ne $AppPool){
                    if($set){
                        #update the apppool
                        Write-Verbose "Updating Apppool to $AppPool for App $Name Under Website $WebSite"
                        Set-ItemProperty -Path IIS:\Sites\$WebSite\$Name -name ApplicationPool -value $AppPool
                    }
                    else{
                        Write-Verbose "Application Pool does not match Desired State"
                        $isDesiredState = $false
                        break
                    }
                }
            }    
        }    
    }
    while($false)
    if(!($set)){Write-Output $isDesiredState}
}

Export-ModuleMember -Function *-TargetResource

