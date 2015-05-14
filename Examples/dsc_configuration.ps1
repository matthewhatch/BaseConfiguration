Configuration BaseNETAppServer2012R2
{
	param(
		[string]$NodeName = 'localhost'
	)

	Import-DSCresource -ModuleName FMGlobalDSCResources_1.1

	Node $NodeName{
		
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

		#Declare Variable to hold previous feature,
		#we'll use this to control order using DependsOn
		$PreviousFeature = ''
		$Features | Foreach {
			
            if([String]::IsNullOrEmpty($PreviousFeature)){
                WindowsFeature ($_).Replace('-','')
			    {
				    Name = $_
				    Ensure = 'Present'
			
			    }
            }
            else{
                WindowsFeature ($_).Replace('-','')
			    {
				    Name = $_
				    Ensure = 'Present'
				    DependsOn = "[WindowsFeature]$PreviousFeature"
			
			    }   
            }
			$PreviousFeature = ($_).Replace('-','')
		}

		File WebSites{
			DestinationPath = 'c:\Websites'
			Type = 'Directory'
			Ensure = 'Present'
			DependsOn = "[WindowsFeature]WebServer" 
		}

		#Add WebSite
		FMGlobal_WebSite TestSite {
			Name = "TestKitchen"
			Ensure = "Present"
			PhysicalPath = "c:\websites"
			State = 'Started'
			DependsOn = "[File]WebSites"
		}

	}
}


