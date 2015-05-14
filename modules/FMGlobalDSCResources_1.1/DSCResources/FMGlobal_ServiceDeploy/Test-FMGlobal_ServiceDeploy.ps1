Import-Module 'C:\Program Files\WindowsPowerShell\Modules\FMGlobalDSCResources_1.1\DSCResources\FMGlobal_ServiceDeploy\FMGlobal_ServiceDeploy.psm1' -Prefix Service -Force
Import-Module FMG.Powershell.UnitTesting 

$params = @{
    Ensure = 'Present'
    Name = 'FMGServiceBusRelayHost'
    VersionFile = 'Mobile.ServiceBus.WCF.Host.WindowsService.exe'
    Source = 'C:\1\HotWorkMobileAppSource\Development'
    Destination = 'C:\1\ServiceTest'
    Version = '1.0.0.0'
    DisplayName = 'FMGServiceBusRelayHost'
}


$TestSetBlock = {
       
    Set-ServiceTargetResource @params
    Test-ServiceTargetResource @params

}

$TestDisplayNameBlock = {
    Set-ServiceTargetResource @params
    Set-Service -Name $params.Name -DisplayName "Something else"
    Test-ServiceTargetResource @params
}

$TestServiceExistsBlock = {

    Set-ServiceTargetResource @params
    $serviceName = Get-Service $params.Name 
    $serviceName -ne $null
}

$RemoveServiceBlock = {
    & sc.exe delete $params.Name
    Set-ServiceTargetResource @params
    Test-ServiceTargetResource @params
}

#Leave the unset test to the end
$TestUnSetBlock = {
    $params.Ensure = 'Absent'

    Set-ServiceTargetResource @params
    Test-ServiceTargetResource @params
}

$TestServiceRemoveBlock = {
    $params.Ensure = 'Absent'
    Set-ServiceTargetResource @params
    Test-ServiceTargetResource @params
}

$SetTarget = New-UnitTest -TestName "Set Service then test, should be true" -ScriptBlock $TestSetBlock -ExpectedResult $true
$TestDisplayName = New-UnitTest -TestName "If display name does not match, Test should return false" -ScriptBlock $TestDisplayNameBlock -ExpectedResult $false
$SetDiplayName = New-UnitTest -TestName "If display name does match, Set-TargetResource should update it" -ScriptBlock $TestSetBlock -ExpectedResult $true
$AddService = New-UnitTest -TestName "If files exist but the service does not, service should be added" -ScriptBlock $RemoveServiceBlock -ExpectedResult $true
$TestServiceExists = New-UnitTest -TestName "Checks if service exists after its set" -ScriptBlock $TestServiceExistsBlock -ExpectedResult $true
$UnsetTarget = New-UnitTest -TestName "Remove the Service, the test should return true" -ScriptBlock $TestUnSetBlock -ExpectedResult $true
$TestServiceRemove = New-UnitTest -TestName "Service should be removed if Ensure is Absent" -ScriptBlock $TestServiceRemoveBlock -ExpectedResult $true


$unitTests = @()
$unitTests += $SetTarget
$unitTests += $TestDisplayName
$unitTests += $SetDiplayName
$unitTests += $AddService
$unitTests += $TestServiceExists
$unitTests += $UnsetTarget
$unitTests += $TestServiceRemove

Show-UnitTestResult -UnitTest $unitTests