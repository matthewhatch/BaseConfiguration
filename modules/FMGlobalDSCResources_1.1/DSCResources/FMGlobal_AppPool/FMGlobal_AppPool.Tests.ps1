$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
$sut = $sut.Replace(".ps1",".psm1")
Import-Module "$here\$sut" -Prefix "AppPool" -Force

$poolParams = Get-AppPoolTargetResource -Name "Powershell"



Describe "Test-TargetResource"{
    $Cred = New-Object -TypeName System.Management.Automation.PSCredential("Somefakeuser",((ConvertTo-SecureString "somefakepassword" -AsPlainText -Force)))
    
    <#Mock Get-AppPoolTargetResource {
        $returnHash = @{
            managedRuntimeVersion = "v4.0"                                                                                                                  
            managedPipelineMode = "Integrated"                                                                                                            
            userName = $Cred.UserName                                                                                                          
            Ensure = "Present"                                                                                                               
            password = $cred                                                                           
            identityType = "SpecificUser"
            Name = "SomeAppPoolThatDoesExist"                                                                                                     
            loadUserProfile = "true"
            Enable32Bit = "true"
            startMode = "OnDemand"
            autoStart = "true"
        }
        return $returnHash
    }#>


    $params = @{
            Ensure = "Present"
            Name = "SomeAppPoolThatDoesntexist"
            AutoStart = "true"
            UserName = $Cred.UserName
            Password = $Cred
    }
    
    It "Should return false when AppPool doesn't exist" {    
        Test-AppPoolTargetResource @params | Should Be $false
    }

    It "Should return true when the appPool doesn't exist and Ensure is set to Absent" {
        $params.Ensure = "Absent"
        Test-AppPoolTargetResource @params | Should Be $true     
    }

    
    It "Should return false when the appPool AutoStart property doesn't match"{
        $AutoStartParams = $poolParams
        if($AutoStartParams.AutoStart -eq "True"){
            $AutoStartParams.AutoStart = "False"
        }else{
            $AutoStartParams.AutoStart = "True"
        }
        
        Test-AppPoolTargetResource @AutoStartParams | Should Be $false
    }

    It "Should return false when the appPool Managed Runtime property does not match" {
        $ManagedRuntimeParams = $poolParams
        if($ManagedRuntimeParams.ManagedRuntimeVersion = "v4.0"){
            $ManagedRuntimeParams.ManagedRuntimeVersion = "v2.0"
        }else{
            $ManagedRuntimeParams.ManagedRuntimeVersion = "v4.0"
        }
        
        Test-AppPoolTargetResource @ManagedRuntimeParams | Should Be $false    
    }

    It "Should return false when the appPool Managed Pipeline Mode does not match"{
        $ManagedPipelineParams = $poolParams
        if($ManagedPipelineParams.ManagedPipelineMode -eq "Integrated"){
            $ManagedPipelineParams.ManagedPipelineMode = "Classic"
        }
        else{
            $ManagedPipelineParams.ManagedPipelineMode = "Integrated"
        }
        Test-AppPoolTargetResource @ManagedPipelineParams | Should Be $false
    }

    It "Should return false when startMode property does not match"{
        $StartModeParams = $poolParams
        if($StartModeParams.StartMode -eq "AlwaysRunning"){
            $StartModeParams.StartMode = "OnDemand"
        }
        else{
            $StartModeParams.StartMode = "AlwaysRunning"
        }

        Test-AppPoolTargetResource @StartModeParams | Should Be $false
    }
    
    It "Should return false when identityType property does not match"{
        $IDTypeParameters = $poolParams
        switch($IDTypeParameters.IdentityType){
            'ApplicationPoolIdentity'{$IDTypeParameters.IdentityType = 'LocalSystem'}
            'LocalSystem'{$IDTypeParameters.IdentityType = 'LocalService'}
            'LocalService'{$IDTypeParameters.IdentityType = 'NetworkService'}
            'NetworkService'{$IDTypeParameters.IdentityType = 'SpecificUser'}
            'SpecificUser'{$IDTypeParameters.IdentityType = 'ApplicationPoolIdentity'}
        }
        Test-AppPoolTargetResource @IDTypeParameters | Should Be $false
    }

    It "Should return false when the username doesn't match" {
        $UserNameParameters = $poolParams
        $UserNameParameters.UserName = $params.UserName
        
        Test-AppPoolTargetResource @UserNameParameters | Should Be $false    
    }

    It "Should return false when the password doesn't match" {
        $passwordParams = $poolParams
        $passwordParams.Password = $params.Password

        Test-AppPoolTargetResource @passwordParams | Should Be $false
    }

    It "Should return false when the loaduserprofile property doesn't match"{
        $profileParams = $poolParams
        if($profileParams.LoadUserProfile = "false"){
            $profileParams.LoadUserProfile = "true"
        }
        else{
            $profileParams.LoadUserProfile = "false"
        }
        
        Test-AppPoolTargetResource @profileParams | Should Be $false
    }

    It "Should return false when the Enable32Bit property doesn't match"{
        $32BitParams = $poolParams
        if($32BitParams.Enable32Bit -eq 'false'){
            $32BitParams.Enable32Bit = 'true'
        }
        else{
            $32BitParams.Enable32Bit = 'false'
        }

        Test-AppPoolTargetResource @32BitParams | Should Be $false

    }

    It "Should return true when the all properties match"{
        $poolParams = Get-AppPoolTargetResource -Name 'Powershell'
        $results = Test-AppPoolTargetResource @poolParams 
        $results | Should Be $true
    }

    <#It "should call the Mock 2 times" {
        Assert-MockCalled Get-AppPoolTargetResource -Exactly 2
    }#>
    
}

Describe "Set-TargetResource"{
    $NewPoolParams = Get-AppPoolTargetResource -Name 'Powershell'
    It "Should Add AppPool that does not exist" {   
        $NewPoolParams.Name = "newApppool"
        Set-AppPoolTargetResource @NewPoolParams
        Test-AppPoolTargetResource @NewPoolParams | Should Be $true
    }

    <#
        Property Test:
            AutoStart, managedRuntimeVersion, managedPipelinemode,startMode,identityType,username,password,loadUserProfile,Enable32Bit
    #>

    It "Should update the AutoStart property if it does not match"{
        $AutoStartPoolParams = $NewPoolParams
        
        if($AutoStartPoolParams.AutoStart -eq 'true'){
            $AutoStartPoolParams.AutoStart = 'false'
        }
        else{
            $AutoStartPoolParams.AutoStart = 'true'
        }

        Set-AppPoolTargetResource @AutoStartPoolParams
        Test-AppPoolTargetResource @AutoStartPoolParams | Should Be $true

    }

    It "Should update the managedRunTimeVersion if it does not match"{
        $ManagedRuntimeParams = $NewPoolParams
        
        if($ManagedRuntimeParams.managedRuntimeVersion -eq 'v4.0'){
            $ManagedRuntimeParams.managedRuntimeVersion = 'v2.0'
        }
        else{
            $ManagedRuntimeParams.managedRuntimeVersion = 'v4.0'
        }

        Set-AppPoolTargetResource @ManagedRuntimeParams
        Test-AppPoolTargetResource @ManagedRuntimeParams | Should Be $true

    }

    It "Should update the managedPipelineMode if it does not match"{
        $ManagedPipelineParams = $NewPoolParams

        if($ManagedPipelineParams.ManagedPipelineMode -eq 'Integrated'){
            $ManagedPipelineParams.ManagedPipelineMode = 'Classic'
        }
        else{
            $ManagedPipelineParams.ManagedPipelineMode = 'Integrated'
        }

        Set-AppPoolTargetResource @ManagedPipelineParams
        Test-AppPoolTargetResource @ManagedPipelineParams | Should Be $true

    }

    It "Should update the startMode if it does not match"{
        $StartModeParams = $NewPoolParams

        if($StartModeParams.StartMode -eq 'AlwaysRunning'){
            $StartModeParams.StartMode = 'OnDemand'
        }
        else{
            $StartModeParams.StartMode = 'AlwaysRunning'
        }
    }

    It "should update the identityType if it does not match" {
        $IDTypeParameters = $NewPoolParams
        switch($IDTypeParameters.IdentityType){
            'ApplicationPoolIdentity'{$IDTypeParameters.IdentityType = 'LocalSystem'}
            'LocalSystem'{$IDTypeParameters.IdentityType = 'LocalService'}
            'LocalService'{$IDTypeParameters.IdentityType = 'NetworkService'}
            'NetworkService'{$IDTypeParameters.IdentityType = 'SpecificUser'}
            'SpecificUser'{$IDTypeParameters.IdentityType = 'ApplicationPoolIdentity'}
        }

        Set-AppPoolTargetResource @IDTypeParameters
        Test-AppPoolTargetResource @IDTypeParameters | Should Be $true
    }

    It "should update the username and password if the identyType is set to Specific User"{
        $IDTypeParameters = $NewPoolParams
        $NewCred = New-Object -TypeName System.Management.Automation.PSCredential("Somefakeuser",((ConvertTo-SecureString "somefakepassword" -AsPlainText -Force)))
        #update the credential
        
        $IDTypeParameters.password = $NewCred
        $IDTypeParameters.username = $NewCred.UserName

        Set-AppPoolTargetResource @IDTypeParameters
        Test-AppPoolTargetResource @IDTypeParameters | Should Be $true
        
    }

    It "Should update the password if it does not match"{
        $IDTypeParameters = $NewPoolParams
        $NewCred = New-Object -TypeName System.Management.Automation.PSCredential("Somefakeuser",((ConvertTo-SecureString "updatedPassword" -AsPlainText -Force)))
        
        $IDTypeParameters.password = $NewCred  
        Set-AppPoolTargetResource @IDTypeParameters
        Test-AppPoolTargetResource @IDTypeParameters | Should Be $true  
    }

    It "should update the loadUserProfile if it does not match"{
        $ProfileParams = $NewPoolParams

        if($ProfileParams.LoadUserProfile -eq 'true'){
            $ProfileParams.LoadUserProfile = 'false'
        }
        else{
            $ProfileParams.LoadUserProfile = 'true'
        }

        Set-AppPoolTargetResource @ProfileParams
        Test-AppPoolTargetResource @ProfileParams | Should Be $true
    }

    It "should update the Enable32Bit if it does not match"{
        $32BitParams = $NewPoolParams

        if($32BitParams.Enable32Bit -eq 'true'){
            $32BitParams.Enable32Bit = 'false'
        }
        else{
            $32BitParams.Enable32Bit = 'true'
        }

        Set-AppPoolTargetResource @32BitParams
        Test-AppPoolTargetResource @32BitParams | Should Be $true

    }

    #cleanup
    Stop-WebAppPool $NewPoolParams.Name -ErrorAction SilentlyContinue
    Remove-WebAppPool $NewPoolParams.Name

}