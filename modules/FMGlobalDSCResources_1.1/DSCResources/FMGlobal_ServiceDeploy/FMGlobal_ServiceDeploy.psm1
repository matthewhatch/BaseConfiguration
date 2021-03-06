<#
    .SYNOPSIS
        DSC Resource for updating Windows service bits

    .DESCRIpTION
        DSC Resource for updating windows service bits, this will not add the service or change any Service configuration.
        The Service Resource should be used in cobjunction with this resource to ensure that the service is present.

        The Service Resource should Depend on the FMGLobal_ServiceDeploy Resource.

#>

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

	try{
        $Service = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$Name'"
        $file = Get-Item $service.PathName
    }
    catch [System.Management.Automation.ItemNotFoundException]{
        __throwError -ErrorId 'ServiceNotFound' -errorCategory ([System.Management.AutoMation.ErrorCategory]::ObjectNotFound) -errorMessage 'The Service Cannot be located'
    }
    if ($Service -ne $null){
        $returnHash = @{
            Name = $Service.Name
            Destination = $File.Directory
            VersionFile = $File.Name
            Version = $File.VersionInfo.ProductVersion
            DisplayName = $Service.DisplayName
        }

        Write-Output $returnHash   
    }

}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$VersionFile,

        [Parameter(Mandatory=$true)]
        [System.String]
        $Name,

        [System.String]
        $DisplayName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.String]
		$Source,

		[Parameter(Mandatory=$true)]
		[System.String]
		$Destination,

		[Parameter(Mandatory=$true)]
        [System.String]
		$Version
	)

	
    $PSBoundParameters.Add("Set",$true)
    __testService @PSBoundParameters

}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$VersionFile,

        [parameter(Mandatory=$true)]
        [System.String]
        $Name,

        [Parameter(Mandatory=$true)]
        [System.String]
        $DisplayName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.String]
		$Source,

		[parameter(Mandatory = $true)]
		[System.String]
		$Destination,

		[System.String]
		$Version
	)

    __testService @PSBoundParameters

}

Function __testService{
    param
	(
		[parameter(Mandatory = $true)]
        [ValidateScript({
            $_ -notmatch '[a-z]:'
        })]
		[System.String]
		$VersionFile,

        [System.String]
        $Name,

        [Parameter(Mandatory=$true)]
        [System.String]
        $Displayname,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.String]
		$Source,

		[parameter(Mandatory = $true)]
		[System.String]
		$Destination,

		[System.String]
		$Version,

        [Switch]
        $Set
	)    

    $IsDesiredState = $true

    $__versionFile = $VersionFile

    do{
        
        #if Ensure is Absent and Destination does not exist, exit
        If(!(Test-Path (Join-Path -Path $Destination -ChildPath $__versionFile)) -and $Ensure -eq "Absent"){
            break
        }


        #if Ensure is Absent and Files exist, return false or Remove Service
        if((Test-Path (Join-Path -Path $Destination -ChildPath $__versionFile)) -and ($Ensure -eq "Absent")){
            Write-Verbose "The files should not exist, but they do, Desired State is set to false"
            $IsDesiredState = $false
            if($Set){
                try{
                    Remove-Item -Path $Destination -Recurse -Force
                    & sc.exe delete $Name | Out-Null
                }
                catch{
                    __throwError -errorID "ServiceRemoveError" -errorMessage "The Service cannot be removed" -ErrorCategory InvalidOperation
                }
            }
            else{break}
        }

        if($Ensure -eq 'Present'){
            #if Destination doesn't exist return false or Copy Files and Create Service
            $destinationPath = Join-Path -Path $Destination -ChildPath $__versionFile
            If(!(Test-Path $destinationPath)){
                Write-Verbose "The destination path does not exist, Desired state is set to false"
                
                $DSCEventMessage = "DSCResourceModule: $($MyInvocation.ScriptName)`n Message: $destinationPath was not found"
                __writeEvent -Message $DSCEventMessage -EventID 901 -EntryType 'Warning'

                $IsDesiredState = $false
                if($Set){
                    Write-Verbose "Copy files from $Source to $Destination"
                    try{
                         __writeEvent -Message "Copying files from $Source to $Destination" -EventID 902 -EntryType 'Information'
                         
                         #Copy the entire Source Directory
                         if(!(Test-Path $Destination)){
                            New-Item -Path $Destination -ItemType Directory -Force | Out-Null
                         }
                         $sourcefiles = Get-ChildItem -Path $Source
                         $sourcefiles | ForEach-Object {Copy-Item -Path $_.FullName -Destination $Destination -Recurse -Force -Exclude "ConfigurationFiles"}
                        
                    }
                    catch{
                        __throwError -errorID "File Copy Error" -errorMessage "Error Copy files from $Source to $Destination" -ErrorCategory InvalidOperation
                    }
                    
                    Write-Verbose "Creating Service $Name"
                    try{
                        __writeEvent -Message "Installing service $Name" -EventID 902 -EntryType 'Information'
                        & sc.exe create $Name binPath=(Join-Path $Destination -ChildPath $__versionFile) | Out-Null
                        Set-Service -Name $Name -DisplayName $DisplayName 
                    }
                    catch{
                        __throwError -errorID 'Service Create Error' -errorMessage "There was an issue creating service $Name" -ErrorCategory InvalidOperation
                    }                   
                         
                }
                break
            }
            else{
                #check the file versions
                $CurrentVersion = (Get-Item (Join-Path -Path $Destination -ChildPath $__versionFile)).VersionInfo.ProductVersion
                if(!($CurrentVersion -eq $Version)){
                    $Message = "Current version $CurrentVersion of $__versionFile does not match expected version $Version"
                    Write-Verbose "The Current Version does not match desired state"
                    __writeEvent -Message $Message -EventID 901 -EntryType 'Warning'
                    $IsDesiredState = $false
                    if($Set){
                        #Stop the Service, Update the files, Start the Service
                        
                        Write-Verbose "Stopping Service $Name"
                        try{
                            Stop-Service $Name -Verbose
                        }
                        catch{
                            __throwError -errorID 'Stopping Sevice Error' -errorMessage "Unable to stop $name" -ErrorCategory InvalidOperation
                        }
                        
                        Write-Verbose "Copy new files from $Source"
                        try{
                            __writeEvent -Message "Updating the version of $Name to $Version"
                            Copy-Item -Path $Source -Destination $Destination -Recurse -Force
                        }
                        catch{
                            __throwError -errorID "File Copy Error" -errorMessage "Unable to Copy Files from $Source to $Destination" -ErrorCategory InvalidOperation
                        }
                        
                        Write-Verbose "Starting Service $Name"
                        try{
                            Start-Service $Name
                        }
                        catch{
                            __throwError -errorID "Start Service Error" -errorMessage "Unable to Start Service $Name" -ErrorCategory InvalidOperation
                        }
                        
                    }
                    else{break}
                }

                $Service = Get-Service | where {$_.Name -eq $Name}
                if($Service -eq $null){
                    $IsDesiredState = $false
                    if($set){
                        #create the service
                        Write-Verbose "Creating Service $Name"
                        try{
                            & sc.exe create $Name binPath=(Join-Path $Destination -ChildPath $__versionFile) | Out-Null
                            Set-Service -name $Name -DisplayName $DisplayName
                        }
                        catch{
                            __throwError -errorID 'Service Create Error' -errorMessage "There was an issue creating service $Name" -ErrorCategory InvalidOperation
                        }  
                    }
                    else{break}
                }else{
                    if(($PSBoundParameters.ContainsKey('DisplayName'))){
                        if($Service.DisplayName -ne $Displayname){
                            $IsDesiredState = $false
                            if($set){
                                Write-Verbose "Updating $Name`'s diplay name to $Displayname"
                                try{
                                    Set-Service -Name $Name -DisplayName $DisplayName 
                                }
                                catch{
                                    __throwError -errorID "Service Update Error" -errorMessage "Unable to update the service Description" -ErrorCategory InvalidOperation
                                }
                            }
                            else{
                                Write-Verbose "Display name does not match desired state"
                                break
                            }   
                        }
                             
                    }
                }
            }
        }     
    }
    while($false)

    if(!($set)){return $IsDesiredState}
}

Function __throwError{
    param(
        [System.String]
        $errorID,

        [System.String]
        $errorMessage,

        [System.Management.Automation.ErrorCategory]
        $ErrorCategory
    )

    $exception = New-Object System.InvalidOperationException $errorMessage 
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null

    <#Add Error to the Event Log#>
    Write-EventLog -LogName 'Microsoft-Windows-Dsc/Operational' -Source 'FMGlobal DSC Event' -EntryType Error -EventId 900 -Message $errorMessage

    $PSCmdlet.ThrowTerminatingError($errorRecord);    
}

Function __writeEvent{
    param(
        [string]$Message,

        [int]$EventID,
        
        [ValidateSet('Error','Warning','Information')]
        [string]$EntryType
    )

    $Source = 'FMGlobal DSC'

    New-EventLog -LogName FMGlobalLog -Source $Source -ErrorAction SilentlyContinue
    Write-EventLog -LogName FMGlobalLog -Source $Source -EntryType $EntryType -EventId $EventID -Message $Message

}
Export-ModuleMember -Function *-TargetResource

