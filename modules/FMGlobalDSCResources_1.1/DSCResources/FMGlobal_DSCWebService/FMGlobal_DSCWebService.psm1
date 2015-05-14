# The Get-TargetResource cmdlet.
function Get-TargetResource
{
    [OutputType([Hashtable])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,
            
        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                         
        [string]$CertificateThumbPrint      
    )

    try
    {
        $webSite = Get-Website -Name $EndpointName

        if ($webSite)
        {
                # Get Full Path for Web.config file    
            $webConfigFullPath = Join-Path $website.physicalPath "web.config"

            $modulePath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath"
            $ConfigurationPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath"

            $UrlPrefix = $website.bindings.Collection[0].protocol + "://"

            $fqdn = $env:COMPUTERNAME
            if ($env:USERDNSDOMAIN)
            {
                $fqdn = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
            }

            $iisPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
                        
            $svcFileName = (Get-ChildItem -Path $website.physicalPath -Filter "*.svc").Name

            $serverUrl = $UrlPrefix + $fqdn + ":" + $iisPort + "/" + $webSite.name + "/" + $svcFileName

            $webBinding = Get-WebBinding -Name $EndpointName
            $certificateThumbPrint = $webBinding.certificateHash

            @{
                EndpointName = $EndpointName
                Port = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
                PhysicalPath = $website.physicalPath
                State = $webSite.state
                ModulePath = $modulePath
                ConfigurationPath = $ConfigurationPath
                DSCServerUrl = $serverUrl
                CertificateThumbPrint = $certificateThumbPrint
            }
        }
    }
    catch
    {
        Write-Error "An error occured while retrieving settings for the website"
    }
}

# The Set-TargetResource cmdlet.
function Set-TargetResource
{
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port,

        # Physical path for the IIS Endpoint on the machine (usually under inetpub/wwwroot)                            
        [string]$PhysicalPath,

        # The IIS Application Pool                         
        [string]$AppPool,

        # Path for Compliance database                         
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComplianceDatabasePath,

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                            
        [string]$CertificateThumbPrint,

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
    
        # Location on the disk where the Modules are stored            
        [string]$ModulePath,

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath,

        # Is the endpoint for a DSC Compliance Server
        [boolean] $IsComplianceServer
    )

    # Initialize with default values        
    $pathPullServer = "$pshome\modules\PSDesiredStateConfiguration\PullServer"
    #$databaseName = "Devices.mdb"
    #$complianceDatabasePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\" + $ComplianceDatabaseFolder
    #$rootDataPath ="$env:PROGRAMFILES\WindowsPowerShell\DscService"
    $jet4provider = "System.Data.OleDb"
    #$jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.mdb;"
    $jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" + $ComplianceDatabasePath
    $eseprovider = "ESENT";
    #$esedatabase = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.edb";
    $esedatabase = $ComplianceDatabasePath

    $culture = Get-Culture
    $language = $culture.TwoLetterISOLanguageName

    $os = [System.Environment]::OSVersion.Version
    $IsBlue = $false;
    if($os.Major -eq 6 -and $os.Minor -eq 3)
    {
        $IsBlue = $true;
    }

    # Use Pull Server values for defaults
    $webConfigFileName = "$pathPullServer\PSDSCPullServer.config"
    $svcFileName = "$pathPullServer\PSDSCPullServer.svc"
    $pswsMofFileName = "$pathPullServer\PSDSCPullServer.mof"
    $pswsDispatchFileName = "$pathPullServer\PSDSCPullServer.xml"

    # Update only if Compliance Server install is requested
    if ($IsComplianceServer)
    {
        $webConfigFileName = "$pathPullServer\PSDSCComplianceServer.config.corrected"
        $svcFileName = "$pathPullServer\PSDSCComplianceServer.svc"
        $pswsMofFileName = "$pathPullServer\PSDSCComplianceServer.mof"
        $pswsDispatchFileName = "$pathPullServer\PSDSCComplianceServer.xml"
    }
                
    Write-Verbose "Create the IIS endpoint"    
    New-PSWSEndpoint -site $EndpointName `
                     -path $PhysicalPath `
                     -cfgfile $webConfigFileName `
                     -port $Port `
                     -appPool $AppPool `
                     -applicationPoolIdentityType LocalSystem `
                     -app $EndpointName `
                     -svc $svcFileName `
                     -mof $pswsMofFileName `
                     -dispatch $pswsDispatchFileName `
                     -asax "$pathPullServer\Global.asax" `
                     -dependentBinaries  "$pathPullServer\Microsoft.Powershell.DesiredStateConfiguration.Service.dll" `
                     -language $language `
                     -dependentMUIFiles  "$pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll" `
                     -certificateThumbPrint $CertificateThumbPrint `
                     -EnableFirewallException $false -Verbose

    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "anonymous"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "basic"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "windows"
        
    if ($IsBlue)
    {
        Write-Verbose "Set values into the web.config that define the repository for BLUE OS"
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase
    }
    else
    {
        Write-Verbose "Set values into the web.config that define the repository for non-BLUE Downlevel OS"
        #$repository = Join-Path "$rootDataPath" "Devices.mdb"
        #Copy-Item "$pathPullServer\Devices.mdb" $repository -Force

        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $jet4database
    }

    if ($IsComplianceServer)
    {    
        Write-Verbose "Compliance Server: Set values into the web.config that indicate this is the admin endpoint"
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "AdminEndPoint" -value "true"
    }
    else
    {
        Write-Verbose "Pull Server: Set values into the web.config that indicate the location of repository, configuration, modules"

        # Create the compliance database directory   
        #$null = New-Item -path $complianceDatabasePath -itemType "directory" -Force

        # Create the application data directory calculated above        
        #$null = New-Item -path $rootDataPath -itemType "directory" -Force
                
        # Set values into the web.config that define the repository and where
        # configuration and modules files are stored. Also copy an empty database
        # into place.        
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $esedatabase

        #$repository = Join-Path $rootDataPath "Devices.mdb"
        #Copy-Item "$pathPullServer\Devices.mdb" $repository -Force
        #Copy-Item "$pathPullServer\Devices.mdb" $complianceDatabasePath -Force

        #$null = New-Item -path "$ConfigurationPath" -itemType "directory" -Force

        Set-AppSettingsInWebconfig -path $PhysicalPath -key "ConfigurationPath" -value $ConfigurationPath

        #$null = New-Item -path "$ModulePath" -itemType "directory" -Force

        Set-AppSettingsInWebconfig -path $PhysicalPath -key "ModulePath" -value $ModulePath	
    }
}

# The Test-TargetResource cmdlet.
function Test-TargetResource
{
	[OutputType([Boolean])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port,

        # Physical path for the IIS Endpoint on the machine (usually under inetpub/wwwroot)                            
        [string]$PhysicalPath,

        # The IIS Application Pool                         
        [string]$AppPool,

        # Path for Compliance database                         
        [string]$ComplianceDatabasePath,

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                            
        [string]$CertificateThumbPrint = "AllowUnencryptedTraffic",

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
    
        # Location on the disk where the Modules are stored            
        [string]$ModulePath,

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath,

        # Is the endpoint for a DSC Compliance Server
        [boolean] $IsComplianceServer
    )

    $desiredConfigurationMatch = $true;

    $website = Get-Website -Name $EndpointName
    $stop = $true

    Do
    {
        Write-Verbose "Check Ensure"
        if(($Ensure -eq "Present" -and $website -eq $null) -or ($Ensure -eq "Absent" -and $website -ne $null))
        {
            $DesiredConfigurationMatch = $false            
            Write-Verbose "The Website $EndpointName is not present"
            break       
        }

        Write-Verbose "Check Port"
        $actualPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
        if ($Port -ne $actualPort)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "Port for the Website $EndpointName does not match the desired state."
            break       
        }

        Write-Verbose "Check Physical Path property"
        if(Test-WebsitePath -EndpointName $EndpointName -PhysicalPath $PhysicalPath)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "Physical Path of Website $EndpointName does not match the desired state."
            break
        }

        Write-Verbose "Check State"
        if($website.state -ne $State -and $State -ne $null)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "The state of Website $EndpointName does not match the desired state."
            break      
        }

        Write-Verbose "Get Full Path for Web.config file"
        $webConfigFullPath = Join-Path $website.physicalPath "web.config"
        if ($IsComplianceServer -eq $false)
        {
            Write-Verbose "Check ModulePath"
            if ($ModulePath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath" -ExpectedAppSettingValue $ModulePath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }    

            Write-Verbose "Check ConfigurationPath"
            if ($ConfigurationPath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath" -ExpectedAppSettingValue $ConfigurationPath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }
        }
        $stop = $false
    }
    While($stop)  

    $desiredConfigurationMatch;
}

# Helper function used to validate website path
function Test-WebsitePath
{
    param
    (
        [string] $EndpointName,
        [string] $PhysicalPath
    )

    $pathNeedsUpdating = $false

    if((Get-ItemProperty "IIS:\Sites\$EndpointName" -Name physicalPath) -ne $PhysicalPath)
    {
        $pathNeedsUpdating = $true
    }

    $pathNeedsUpdating
}

# Helper function to Test the specified Web.Config App Setting
function Test-WebConfigAppSetting
{
    param
    (
        [string] $WebConfigFullPath,
        [string] $AppSettingName,
        [string] $ExpectedAppSettingValue
    )
    
    $returnValue = $true

    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement() 

        foreach ($item in $root.appSettings.add) 
        { 
            if( $item.key -eq $AppSettingName ) 
            {                 
                break
            } 
        }

        if($item.value -ne $ExpectedAppSettingValue)
        {
            $returnValue = $false
            Write-Verbose "The state of Web.Config AppSetting $AppSettingName does not match the desired state."
        }

    }
    $returnValue
}

# Helper function to Get the specified Web.Config App Setting
function Get-WebConfigAppSetting
{
    param
    (
        [string] $WebConfigFullPath,
        [string] $AppSettingName
    )
    
    $appSettingValue = ""
    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement() 

        foreach ($item in $root.appSettings.add) 
        { 
            if( $item.key -eq $AppSettingName ) 
            {     
                $appSettingValue = $item.value          
                break
            } 
        }        
    }
    
    $appSettingValue
}

# Helper to get current script Folder
function Get-ScriptFolder
{
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

# Allow this Website to enable/disable specific Auth Schemes by adding <location> tag in applicationhost.config
function Update-LocationTagInApplicationHostConfigForAuthentication
{
    param (
        # Name of the WebSite        
        [String] $WebSite,

        # Authentication Type
        [ValidateSet('anonymous', 'basic', 'windows')]		
        [String] $Authentication
    )

    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null

    $webAdminSrvMgr = new-object Microsoft.Web.Administration.ServerManager

    $appHostConfig = $webAdminSrvMgr.GetApplicationHostConfiguration()

    $authenticationType = $Authentication + "Authentication"
    $appHostConfigSection = $appHostConfig.GetSection("system.webServer/security/authentication/$authenticationType", $WebSite)
    $appHostConfigSection.OverrideMode="Allow"
    $webAdminSrvMgr.CommitChanges()
}

# Validate supplied configuration to setup the PSWS Endpoint
# Function checks for the existence of PSWS Schema files, IIS config
# Also validate presence of IIS on the target machine
#
function Initialize-Endpoint
{
    param (
        $site,
        $path,
        $cfgfile,
        $port,
        $app,
        $appPool,
        $applicationPoolIdentityType,
        $svc,
        $mof,
        $dispatch,        
        $asax,
        $dependentBinaries,
        $language,
        $dependentMUIFiles,
        $psFiles,
        $removeSiteFiles = $false,
        $certificateThumbPrint)
    
    if (!(Test-Path $cfgfile))
    {        
        throw "ERROR: $cfgfile does not exist"    
    }            
    
    if (!(Test-Path $svc))
    {        
        throw "ERROR: $svc does not exist"    
    }            
    
    if (!(Test-Path $mof))
    {        
        throw "ERROR: $mof does not exist"  
    }   	
    
    if (!(Test-Path $asax))
    {        
        throw "ERROR: $asax does not exist"  
    }  

    if ($certificateThumbPrint -ne "AllowUnencryptedTraffic")
    {    
        Write-Verbose "Verify that the certificate with the provided thumbprint exists in CERT:\LocalMachine\MY\"
        $certificate = Get-childItem CERT:\LocalMachine\MY\ | Where {$_.Thumbprint -eq $certificateThumbPrint}
        if (!$Certificate) 
        { 
             throw "ERROR: Certificate with thumbprint $certificateThumbPrint does not exist in CERT:\LocalMachine\MY\"
        }  
    }     
    
    Test-IISInstall
    
    #$appPool = "PSWS"
    
    #Write-Verbose "Delete the App Pool if it exists"
    #Remove-AppPool -apppool $appPool
    #Write-Verbose "App Pool deleted if it existed"
    
    Write-Verbose "Remove the site if it already exists"
    Update-Site -siteName $site -siteAction Remove
    
    if ($removeSiteFiles)
    {
        if(Test-Path $path)
        {
            Remove-Item -Path $path -Recurse -Force
        }
    }
    
    Write-Verbose "Copying files..."
    Copy-Files -path $path -cfgfile $cfgfile -svc $svc -mof $mof -dispatch $dispatch -asax $asax -dependentBinaries $dependentBinaries -language $language -dependentMUIFiles $dependentMUIFiles -psFiles $psFiles
    Write-Verbose "Files copied..."
    
    #Write-Verbose "Update all sites..."
    #Update-AllSites Stop
    #Update-DefaultAppPool Stop
    #Update-DefaultAppPool Start
    #Write-Verbose "All sites updated..."
    
    Write-Verbose "Creating new web site..."
    New-IISWebSite -site $site -path $path -port $port -app $app -apppool $appPool -applicationPoolIdentityType $applicationPoolIdentityType -certificateThumbPrint $certificateThumbPrint
    Write-Verbose "Web site created..."
}

# Validate if IIS and all required dependencies are installed on the target machine
#
function Test-IISInstall
{
        Write-Verbose "Checking IIS requirements"
        $iisVersion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp -ErrorAction silentlycontinue).MajorVersion + (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp -ErrorAction silentlycontinue).MinorVersion
        
        if ($iisVersion -lt 7.0) 
        {
            throw "ERROR: IIS Version detected is $iisVersion , must be running higher than 7.0"            
        }        
        
        $wsRegKey = (Get-ItemProperty hklm:\SYSTEM\CurrentControlSet\Services\W3SVC -ErrorAction silentlycontinue).ImagePath
        if ($wsRegKey -eq $null)
        {
            throw "ERROR: Cannot retrive W3SVC key. IIS Web Services may not be installed"            
        }        
        
        if ((Get-Service w3svc).Status -ne "running")
        {
            throw "ERROR: service W3SVC is not running"
        }
}

# Verify if a given IIS Site exists
#
function Test-IISSiteExists
{
    param ($siteName)

    $site = "IIS:\Sites\" + $siteName
    #if (Get-Website -Name $siteName)
    if (Get-Item $site -ErrorAction SilentlyContinue)
    {
        return $true
    }
    
    return $false
}

# Perform an action (such as stop, start, delete) for a given IIS Site
#
function Update-Site
{
    param (
        [Parameter(ParameterSetName = 'SiteName', Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$siteName,

        [Parameter(ParameterSetName = 'Site', Mandatory, Position = 0)]        
        $site,

        [Parameter(ParameterSetName = 'SiteName', Mandatory, Position = 1)]
        [Parameter(ParameterSetName = 'Site', Mandatory, Position = 1)]
        [String]$siteAction)
    
    [String]$name = $null
    if ($PSCmdlet.ParameterSetName -eq 'SiteName')
    {
        $name = $siteName
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Site')
    {   
        $name = $site.Name
    }
    
    if (Test-IISSiteExists $name)
    {        
        switch ($siteAction) 
        { 
            "Start"  
            {
                Write-Verbose ("Starting site: " + $name)
                Start-Website -Name $name
                Write-Verbose ("Site started...")
            } 
            
            "Stop"   
            {
                Write-Verbose ("Stopping site: " + $name)
                Stop-Website -Name $name -ErrorAction SilentlyContinue
                Write-Verbose ("Site stopped...")
            } 
            
            "Remove" 
            {
                Write-Verbose ("Removing site: " + $name)
                Remove-Website -Name $name
                Write-Verbose ("Site removed...")
            }
        }
    }
}

# Delete the given IIS Application Pool
# This is required to cleanup any existing conflicting apppools before setting up the endpoint
#
function Remove-AppPool
{
    param ($appPool)    
    
    Remove-WebAppPool -Name $appPool -ErrorAction SilentlyContinue
}

# Perform given action(start, stop, delete) on all IIS Sites
#
function Update-AllSites
{
    param ($action)    
    
    foreach ($site in Get-Website)
    {
        Update-Site $site $action
    }
}

# Perform given action(start, stop) on the default app pool
#
function Update-DefaultAppPool
{
    param ($action) 
    
    switch ($action) 
    { 
        "Start"  {Start-WebAppPool -Name "DefaultAppPool"} 
        "Stop"   {Stop-WebAppPool -Name "DefaultAppPool"} 
        "Remove" {Remove-WebAppPool -Name "DefaultAppPool"}
    }
}

# Generate an IIS Site Id while setting up the endpoint
# The Site Id will be the max available in IIS config + 1
#
function New-SiteID
{
    return ((Get-Website | % { $_.Id } | Measure-Object -Maximum).Maximum + 1)
}

# Validate the PSWS config files supplied and copy to the IIS endpoint in inetpub
#
function Copy-Files
{
    param (
        $path,
        $cfgfile,
        $svc,
        $mof,    
        $dispatch,
        $asax,
        $dependentBinaries,
        $language,
        $dependentMUIFiles,
        $psFiles)    
    
    if (!(Test-Path $cfgfile))
    {
        throw "ERROR: $cfgfile does not exist"    
    }
    
    if (!(Test-Path $svc))
    {
        throw "ERROR: $svc does not exist"    
    }
    
    if (!(Test-Path $mof))
    {
        throw "ERROR: $mof does not exist"    
    }

    if (!(Test-Path $asax))
    {
        throw "ERROR: $asax does not exist"    
    }
    
    if (!(Test-Path $path))
    {
        $null = New-Item -ItemType container -Path $path        
    }
    
    foreach ($dependentBinary in $dependentBinaries)
    {
        if (!(Test-Path $dependentBinary))
        {					
            throw "ERROR: $dependentBinary does not exist"  
        } 	
    }

    foreach ($dependentMUIFile in $dependentMUIFiles)
    {
        if (!(Test-Path $dependentMUIFile))
        {					
            throw "ERROR: $dependentMUIFile does not exist"  
        } 	
    }
    
    Write-Verbose "Create the bin folder for deploying custom dependent binaries required by the endpoint"
    $binFolderPath = Join-Path $path "bin"
    Write-Verbose ("Creating BIN folder: " + $binFolderPath)
    $null = New-Item -path $binFolderPath  -itemType "directory" -Force
    Write-Verbose ("Coping binaries BIN folder: " + $dependentBinaries)
    Copy-Item $dependentBinaries $binFolderPath -Force
    Write-Verbose "Binaries copied..."
    
    if ($language)
    {
        $muiPath = Join-Path $binFolderPath $language

        if (!(Test-Path $muiPath))
        {
            $null = New-Item -ItemType container $muiPath        
        }
        Copy-Item $dependentMUIFiles $muiPath -Force
    }
    
    foreach ($psFile in $psFiles)
    {
        if (!(Test-Path $psFile))
        {					
            throw "ERROR: $psFile does not exist"  
        } 	
        
        Copy-Item $psFile $path -Force
    }		
    
    Write-Verbose ("Copying " + $cfgfile)
    Copy-Item $cfgfile (Join-Path $path "web.config") -Force
    Write-Verbose ("Copying " + $svc)
    Copy-Item $svc $path -Force
    Write-Verbose ("Copying " + $mof)
    Copy-Item $mof $path -Force
    
    if ($dispatch)
    {
        Write-Verbose ("Copying " + $dispatch)
        Copy-Item $dispatch $path -Force
    }  
    
    if ($asax)
    {
        Write-Verbose ("Copying " + $asax)
        Copy-Item $asax $path -Force
    }
}

# Setup IIS Apppool, Site and Application
#
function New-IISWebSite
{
    param (
        $site,
        $path,    
        $port,
        $app,
        $appPool,        
        $applicationPoolIdentityType,
        $certificateThumbPrint)    
    
    $siteID = New-SiteID
    
	$appPoolPath = "IIS:\AppPools\" + $appPool
    $existingAppPool = Get-Item -Path $appPoolPath -ErrorAction Ignore
	if ($existingAppPool -eq $null)
	{
		Write-Verbose ("Adding new web app pool: " + $appPool)
		#$null = New-WebAppPool -Name $appPool
		New-WebAppPool -Name $appPool
		Write-Verbose "New web app pool added..."
	}

    $appPoolIdentity = 4
    if ($applicationPoolIdentityType)
    {   
        # LocalSystem = 0, LocalService = 1, NetworkService = 2, SpecificUser = 3, ApplicationPoolIdentity = 4        
        if ($applicationPoolIdentityType -eq "LocalSystem")
        {
            $appPoolIdentity = 0
        }
        elseif ($applicationPoolIdentityType -eq "LocalService")
        {
            $appPoolIdentity = 1
        }      
        elseif ($applicationPoolIdentityType -eq "NetworkService")
        {
            $appPoolIdentity = 2
        }        
    } 

    Write-Verbose "Set App Pool properties..."
    $appPoolItem = Get-Item IIS:\AppPools\$appPool
    $appPoolItem.managedRuntimeVersion = "v4.0"
    $appPoolItem.enable32BitAppOnWin64 = $true
    $appPoolItem.processModel.identityType = $appPoolIdentity
    $appPoolItem | Set-Item
    Write-Verbose "App Pool properties set..."
    
    Write-Verbose "Add and Set Site Properties"
    if ($certificateThumbPrint -eq "AllowUnencryptedTraffic")
    {
        $webSite = New-WebSite -Name $site -Id $siteID -Port $port -IPAddress "*" -PhysicalPath $path -ApplicationPool $appPool
    }
    else
    {
        $webSite = New-WebSite -Name $site -Id $siteID -Port $port -IPAddress "*" -PhysicalPath $path -ApplicationPool $appPool -Ssl

        # Remove existing binding for $port
        Remove-Item IIS:\SSLBindings\0.0.0.0!$port -ErrorAction Ignore

        # Create a new binding using the supplied certificate
        $null = Get-Item CERT:\LocalMachine\MY\$certificateThumbPrint | New-Item IIS:\SSLBindings\0.0.0.0!$port
    }
        
    #Write-Verbose "Delete application"
    #Remove-WebApplication -Name $app -Site $site -ErrorAction SilentlyContinue
    
    #Write-Verbose "Add and Set Application Properties"
    #$null = New-WebApplication -Name $app -Site $site -PhysicalPath $path -ApplicationPool $appPool
    
    Update-Site -siteName $site -siteAction Start    
}

# Allow Clients outsite the machine to access the setup endpoint on a User Port
#
function New-FirewallRule
{
    param ($firewallPort)
    
    Write-Verbose "Disable Inbound Firewall Notification"
    Set-NetFirewallProfile -Profile Domain,Public,Private –NotifyOnListen False
    
    Write-Verbose "Add Firewall Rule for port $firewallPort"    
    $null = New-NetFirewallRule -DisplayName "Allow Port $firewallPort for PSWS" -Direction Inbound -LocalPort $firewallPort -Protocol TCP -Action Allow
}

# Enable & Clear PSWS Operational/Analytic/Debug ETW Channels
#
function Enable-PSWSETW
{    
    # Disable Analytic Log
    & $script:wevtutil sl Microsoft-Windows-ManagementOdataService/Analytic /e:false /q | Out-Null    

    # Disable Debug Log
    & $script:wevtutil sl Microsoft-Windows-ManagementOdataService/Debug /e:false /q | Out-Null    

    # Clear Operational Log
    & $script:wevtutil cl Microsoft-Windows-ManagementOdataService/Operational | Out-Null    

    # Enable/Clear Analytic Log
    & $script:wevtutil sl Microsoft-Windows-ManagementOdataService/Analytic /e:true /q | Out-Null    

    # Enable/Clear Debug Log
    & $script:wevtutil sl Microsoft-Windows-ManagementOdataService/Debug /e:true /q | Out-Null    
}

<#
.Synopsis
   Create PowerShell WebServices IIS Endpoint
.DESCRIPTION
   Creates a PSWS IIS Endpoint by consuming PSWS Schema and related dependent files
.EXAMPLE
   New a PSWS Endpoint [@ http://Server:39689/PSWS_Win32Process] by consuming PSWS Schema Files and any dependent scripts/binaries
   New-PSWSEndpoint -site Win32Process -path $env:HOMEDRIVE\inetpub\wwwroot\PSWS_Win32Process -cfgfile Win32Process.config -port 39689 -app Win32Process -svc PSWS.svc -mof Win32Process.mof -dispatch Win32Process.xml -dependentBinaries ConfigureProcess.ps1, Rbac.dll -psFiles Win32Process.psm1
#>
function New-PSWSEndpoint
{
[CmdletBinding()]
    param (
        
        # Unique Name of the IIS Site        
        [String] $site = "PSWS",
        
        # Physical path for the IIS Endpoint on the machine (under inetpub/wwwroot)        
        [String] $path = "$env:HOMEDRIVE\inetpub\wwwroot\PSWS",
        
        # Web.config file        
        [String] $cfgfile = "web.config",
        
        # Port # for the IIS Endpoint        
        [Int] $port = 8080,
        
        # IIS Application Name for the Site        
        [String] $app = "PSWS",
        
        # IIS App Pool Name       
        [String] $appPool,

        # IIS App Pool Identity Type - must be one of LocalService, LocalSystem, NetworkService, ApplicationPoolIdentity		
        [ValidateSet('LocalService', 'LocalSystem', 'NetworkService', 'ApplicationPoolIdentity')]		
        [String] $applicationPoolIdentityType,
        
        # WCF Service SVC file        
        [String] $svc = "PSWS.svc",
        
        # PSWS Specific MOF Schema File
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $mof,
        
        # PSWS Specific Dispatch Mapping File [Optional]
        [ValidateNotNullOrEmpty()]		
        [String] $dispatch,    
        
        # Global.asax file [Optional]
        [ValidateNotNullOrEmpty()]
        [String] $asax,
        
        # Any dependent binaries that need to be deployed to the IIS endpoint, in the bin folder
        [ValidateNotNullOrEmpty()]
        [String[]] $dependentBinaries,

         # MUI Language [Optional]
        [ValidateNotNullOrEmpty()]
        [String] $language,

        # Any dependent binaries that need to be deployed to the IIS endpoint, in the bin\mui folder [Optional]
        [ValidateNotNullOrEmpty()]
        [String[]] $dependentMUIFiles,
        
        # Any dependent PowerShell Scipts/Modules that need to be deployed to the IIS endpoint application root
        [ValidateNotNullOrEmpty()]
        [String[]] $psFiles,
        
        # True to remove all files for the site at first, false otherwise
        [Boolean]$removeSiteFiles = $false,

        # Enable Firewall Exception for the supplied port        
        [Boolean] $EnableFirewallException,

        # Enable and Clear PSWS ETW        
        [switch] $EnablePSWSETW,
        
        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [String] $certificateThumbPrint = "AllowUnencryptedTraffic")
    
    $script:wevtutil = "$env:windir\system32\Wevtutil.exe"
       
    $svcName = Split-Path $svc -Leaf
    $protocol = "https:"
    if ($certificateThumbPrint -eq "AllowUnencryptedTraffic")
    {
        $protocol = "http:"
    }

    # Get Machine Name and Domain
    $cimInstance = Get-CimInstance -ClassName Win32_ComputerSystem
    
    Write-Verbose ("SETTING UP ENDPOINT at - $protocol//" + $cimInstance.Name + "." + $cimInstance.Domain + ":" + $port + "/" + $site + "/" + $svcName)
    Initialize-Endpoint -site $site -path $path -cfgfile $cfgfile -port $port -app $app -appPool $appPool `
                        -applicationPoolIdentityType $applicationPoolIdentityType -svc $svc -mof $mof `
                        -dispatch $dispatch -asax $asax -dependentBinaries $dependentBinaries `
                        -language $language -dependentMUIFiles $dependentMUIFiles -psFiles $psFiles `
                        -removeSiteFiles $removeSiteFiles -certificateThumbPrint $certificateThumbPrint
    
    if ($EnableFirewallException -eq $true)
    {
        Write-Verbose "Enabling firewall exception for port $port"
        $null = New-FirewallRule $port
    }

    if ($EnablePSWSETW)
    {
        Enable-PSWSETW
    }
    
    Update-AllSites start
    
}

<#
.Synopsis
   Set the option into the web.config for an endpoint
.DESCRIPTION
   Set the options into the web.config for an endpoint allowing customization.
.EXAMPLE
#>
function Set-AppSettingsInWebconfig
{
    param (
                
        # Physical path for the IIS Endpoint on the machine (possibly under inetpub/wwwroot)
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $path,
        
        # Key to add/update
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $key,

        # Value 
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $value

        )
                
    $webconfig = Join-Path $path "web.config"
    [bool] $Found = $false

    if (Test-Path $webconfig)
    {
        $xml = [xml](get-content $webconfig)
        $root = $xml.get_DocumentElement() 

        foreach( $item in $root.appSettings.add) 
        { 
            if( $item.key -eq $key ) 
            { 
                $item.value = $value; 
                $Found = $true;
            } 
        }

        if( -not $Found)
        {
            $newElement = $xml.CreateElement("add")                               
            $nameAtt1 = $xml.CreateAttribute("key")                    
            $nameAtt1.psbase.value = $key;                                
            $null = $newElement.SetAttributeNode($nameAtt1)
                                   
            $nameAtt2 = $xml.CreateAttribute("value")                      
            $nameAtt2.psbase.value = $value;                       
            $null = $newElement.SetAttributeNode($nameAtt2)       
                                   
            $null = $xml.configuration["appSettings"].AppendChild($newElement)   
        }
    }

    $xml.Save($webconfig) 
}


Export-ModuleMember -Function *-TargetResource