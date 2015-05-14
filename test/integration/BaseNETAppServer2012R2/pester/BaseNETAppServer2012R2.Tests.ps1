Describe 'Roles and Features'{
    
    $Features = @(
            'Web-Server',
            'Web-WebServer',
            'Web-Log-Libraries',
            'Web-Http-Tracing',
            'Web-Custom-Logging',
            'Web-ODBC-Logging',
            'Web-Asp-Net45',
            'NET-Framework-45-Core',
            'NET-Framework-45-ASPNET',
            'NET-WCF-HTTP-Activation45',
            'NET-WCF-MSMQ-Activation45',
            'NET-WCF-Pipe-Activation45',
            'NET-WCF-TCP-Activation45',
            'NET-WCF-TCP-Portsharing45',
            'MSMQ-Server',
            'WAS-Process-Model',
            'WAS-Config-APIs'
        )

    $Features | ForEach {
        It "Should have the $_ Role Enabled"{
            $Role = Get-WindowsFeature -Name $_
            $Role.Installed | Should Be $true 
        }
    }

}

Describe 'Web Site SetUp'{

    It 'Should have a folder c:\websites' {
        $webDir = Get-Item c:\websites
        $webDir | Should Exist   
    }

    It 'Should have Web Site TestKitchen'{
        (Get-Item iis:\Sites\TestKitchen).Name | Should Be 'TestKitchen'
    }

    It 'TestKitchen site should be started'{
        (Get-Item iis:\Sites\TestKitchen).State | Should Be 'started'
    }
}