function Get-TargetResource{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    #return a hashtable with Name, Physicalpath, State, ApplicationPool, BindingInfo
    $Site = Get-WebSite | Where {$_.Name -eq $Name} | select Name,PhysicalPath, Bindings, applicationPool, State
    
    $return = @{
        Name = $Site.Name
        PhysicalPath = $Site.PhysicalPath
        State = $site.State
        ApplicationPool = $Site.ApplicationPool
        Bindings = $Site.Bindings
    }    
    Write-Output $return
}

function Set-TargetResource 
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param 
    (       
        [ValidateSet("Present", "Absent")]
        [System.String]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]$PhysicalPath,

        [ValidateSet("Started", "Stopped")]
        [System.String]$State = "Started",

        [System.String]$ApplicationPool,

        [Microsoft.Management.Infrastructure.CimInstance[]]$BindingInfo
    )
    
    if(!(Test-WebSiteTargetResource @PSBoundParameters)){
        Write-Verbose "Updating Web Site $Name Settings"

        #It seems strange to have to check all settings again
        $site = Get-WebSite | where {$_.name -eq $name}

        do{
            if($Ensure -eq "Present" -and $site -eq $null){
                Write-Verbose "Adding site $Name"
                $PSBoundParameters.Remove("Ensure") | Out-Null
                $PSBoundParameters.Remove("State") | Out-Null
                $PSBoundParameters.Remove("BindingInfo") | Out-Null

                $site = New-Website @PSBoundParameters
                Write-Verbose "Site $Name added"
                
                Write-Verbose "Checking Bindings..."
                foreach($newBinding in $BindingInfo){
                   Write-Verbose "`tChecking $($newBinding.Protocol)"
                   $newBinding.Add('Name',$Name)
                   
                   if($newBinding.ContainsKey("Thumbprint")){
                        $newBinding.Remove("Thumbprint")
                   }
                                 
                    try{
                           
                        if(!(__ValidateBinding -Bindings $newBinding -Name $Name)){__UpdateBindings -Bindings $newBinding -Name $Name}
                            
                        #check for thumbprint
                        if($newBinding.Protocol -eq 'https' -and (!([string]::IsNullOrEmpty($newBinding.Thumbprint)))){
                            Write-Verbose "Adding SSL Certificate $($newBinding.Thumbprint)"
                            __updateThumbprint -IPaddress $newBinding.IPAddress -Port $newBinding.Port -Thumbprint $newBinding.Thumbprint
                        }
                    }
                    catch{
                        Write-Warning "There was an issue Binding $($newBinding.Protocol)" 
                    }
                   
                }
                
                
                if($State -eq "Started"){
                    Write-Verbose "Starting $($site.name)"
                    Start-Website $site.name  
                }
                break
            }

            if($Ensure -eq "Absent" -and $site -ne $null){
                Write-Verbose "Removing $($site.Name)"
                Remove-Website -Name $site.Name
                break
            }

            #Check Physical Path
            if($Site.PhysicalPath -ne $PhysicalPath){
                Write-Verbose "Updating Physical Path for $($site.name) to $PhysicalPath"
                Set-ItemProperty IIS:\Sites\$name -Name PhysicalPath -Value $PhysicalPath
            }

            #check AppPool
            if($site.ApplicationPool -ne $ApplicationPool){
                Write-Verbose "Updating $($site.name)'s AppPool to $ApplicationPool"
                Set-ItemProperty IIS:\Sites\$name -Name ApplicationPool -Value $ApplicationPool
            }

            #check State
            if($state -ne $site.state){
                if($State -eq "Started"){
                    Write-Verbose "Starting $($site.name)"
                    Start-WebSite $site.name
                }
                if($State -eq "Stopped"){
                    "Stopping $($site.name)"
                    Stop-Website $site.name
                }
            }
            
            foreach($binding in $BindingInfo){
                if(!(__ValidateBinding -Bindings $Binding -Name $Name)){
                    Write-Verbose "Updating $Name Binding Information"
                    __UpdateBindings -Bindings $binding -Name $Name
                }
            }
            


        }
        while($false)
    }
    else{
       Write-Verbose "Web Site $Name is all set, nothing to update"
    }
}

function Test-TargetResource{
    param 
    (       
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PhysicalPath,

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",

        [string]$ApplicationPool,

        [Microsoft.Management.Infrastructure.CimInstance[]]$BindingInfo
        #[System.Collections.Hashtable[]]$BindingInfo
    )
    Import-Module WebAdministration
      Write-Verbose "Starting the Test-TargetResource Updated on 10/21/2014"
    [System.Boolean]$isDesiredState = $true
    
    $isDesiredState = $true
    $site = Get-WebSite | where {$_.name -eq $Name}
    Write-Verbose " Found $($site.count) site(s)"
    Do{
        #check Ensure
        if($Ensure -eq "Absent" -and $site -eq $null)
        {
            $isDesiredState = $true
            break
        }
        
        if(($ensure -eq "Present" -and $site -eq $null) -or ($Ensure -eq "Absent" -and $site -ne $null)){
            Write-Verbose "Ensure is not set to the Desired State"
            $isDesiredState = $false
            break
        }
        
        #check physical path
        if($site.PhysicalPath -ne $PhysicalPath){
            Write-Verbose "Physical Path is not set to Desired state: $PhysicalPath"
            $isDesiredState =$false
            break
        }

        #state
        if($PSBoundParameters.ContainsKey("State") -and $site.State -ne $State){
            Write-Verbose "State does not match desired state: $State"
            $isDesiredState = $false
            break
        }

        #ApplicationPool
        if($PSBoundParameters.ContainsKey("ApplicationPool") -and $Site.ApplicationPool -ne $ApplicationPool){
            Write-Verbose "Application Pool does not match desired state: $ApplicationPool"
            $isDesiredState = $false
            break
        }

        #bindings
        if($PSBoundParameters.ContainsKey("BindingInfo")){
            Write-Verbose "Validating $($BindingInfo.Count) Binding(s)"
            foreach ($binding in $BindingInfo){
                Write-Verbose "Validating $($binding.protocol)"
                if(!(__ValidateBinding -Bindings $binding -Name $Name)){
                    Write-Verbose "Binding information does not match Desired State"
                    $isDesiredState = $false
                    break
                }
            }
        }
    }
    While($false)
    return $isDesiredState    
}

function __ValidateBinding{
    param(
        #[System.Collections.Hashtable]
        [Microsoft.Management.Infrastructure.CimInstance]
        $Bindings,

        [string]$Name
    )
    $SiteBindings = (Get-ItemProperty -Path "IIS:\Sites\$Name" -name bindings).Collection #Get-WebBinding -Name $Name
    
        $isValid = $false
        do{
            foreach($siteBinding in $SiteBindings){
                $BindingsArray = $SiteBinding.bindingInformation.ToString().Split(':')
                $IPAddress = $BindingsArray[0]
                $Port = $BindingsArray[1]  

                if($Bindings.Protocol -match 'msmq' -and $Bindings.Protocol -eq $siteBinding.Protocol){
                    Write-Verbose 'MSMQ Binding Found'
                    $isValid = $true
                    break
                }
                 
                
                if($Bindings.Protocol -eq 'net.tcp' -or $Bindings.Protocol -eq 'net.pipe'){
                    Write-Verbose "Checking $($SiteBinding.Protocol)"
                    
                    if(!([string]::IsNullOrEmpty($Bindings.Port))){
                        $bindingInfo = "$($Bindings.Port):*"
                    }
                    else{
                        $bindingInfo = "*"
                    }
                    
                    if($bindingInfo -eq $SiteBinding.bindingInformation){
                       
                        $isValid = $true
                        break
                    }    
                }
                    
                if(($Bindings.Port -eq $port) -and ($Bindings.IPaddress -eq $IPAddress) -and ($Bindings.Protocol -eq $siteBinding.Protocol)){
                    if($SiteBinding.Protocol -eq 'https' -and !([string]::IsNullOrEmpty($Bindings.Thumbprint))){
                        #Check certificate
                        Write-Verbose "Checking Thumbprint"
                        __checkThumbprint -IPaddress $Bindings.IPAddress -Port $Bindings.Port -Thumbprint $Bindings.Thumbprint
                    }
                    $isValid = $true
                    break
                }
            }   
        }
        while($false)
        
      
    return $isValid
       
}

function __UpdateBindings{
    param(
        [Microsoft.Management.Infrastructure.CimInstance]
        $Bindings,

        [string]$Name
    )

    try{
        #add new Binding
        $params = @{
            Name = $Name
        }
        
        if($Bindings.Protocol -match 'msmq'){
            __addMSMQBinding -Protocol $Bindings.Protocol -Name $Name
        }
        elseif($Bindings.Protocol -match 'net.tcp' -or $Bindings.Protocol -match 'net.pipe'){
            __addnetbindings -Name $Name -Protocol $Bindings.Protocol -Port $Bindings.Port
        }
        else{
            if($Bindings.IPAddress -ne $null){$params.Add("IPAddress", $Bindings.IPAddress)}
            if($Bindings.Port -ne $null){$params.Add("Port", $Bindings.Port)}
            if($Bindings.Protocol -ne $null){$params.Add("Protocol",$Bindings.Protocol)}

            New-WebBinding @params
            Write-Verbose "New Binding $($Bindings.Protocol) Added to $Name"
        }
    }
    catch
    {   
        #If there is a conflict update the current setting using Set-WebBinding
        Write-Warning "there was an issue adding binding to $Name"
    }

}

function __checkThumbprint{
    param(
        [string]$IPaddress,

        [string]$Port,

        [string]$Thumbprint
    )
    $isValid = $false
    if((Get-Item IIS:\SslBindings\$IPaddress!$Port).Thumbprint -eq $Thumbprint){
        Write-Verbose "Thumbprint matches"   
    }
    else{
        Write-Verbose "Thumbprint does not match $Thumbprint"
        __updateThumbprint @PSBoundParameters
    }
}

function __updateThumbprint{
    param(
    
        [string]$IPaddress,

        [string]$Port,

        [string]$Thumbprint
    )
    Write-Verbose "Updating $($IPaddress):$Port with Thumbptint $Thumbprint"
    Set-ItemProperty IIS:\SslBindings\$IPaddress!$Port -Name 'Thumbprint' -Value $Thumbprint 
}

function __addMSMQBinding{
    param(
        [string]$Protocol,

        [string]$Name
    )
    
    New-ItemProperty -path "IIS:\\Sites\$Name" -name bindings -value @{protocol=$Protocol; bindingInformation="localhost"}
    Write-Verbose "New Binding $Protocol added to $Name"
}

function __addnetbindings{
    param(
        [string]$Protocol,

        [string]$Port,

        [string]$Name
    )

    if([string]::IsNullOrEmpty($port)){
        $bindingInformation = "*"
    }else{
        $bindingInformation = "$port`:*"    
    }
    
    New-ItemProperty -Path "IIS:\Sites\$Name" -name bindings -Value @{protocol=$Protocol; bindingInformation=$bindingInformation}
    Write-Verbose "New Binding $bindingInformation added to $Name"

}

Export-ModuleMember -Function *-TargetResource

