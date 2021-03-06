function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Thumbprint
	)

	 Import-Module fmg.powershell.common
    
    $Certificate = Get-Certificate | where {$_.Thumbprint -eq $Thumbprint}
    
    $properties = @{
        Subject = $Certificate.Subject
        Thumbprint = $Certificate.Thumbprint
    }

    Write-Output $properties
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Thumbprint,

		[System.String]
		$Path,

		[System.String]
		$Password
	)

	 if(!(Test-TargetResource @PSBoundParameters)){
        Write-Verbose "adding certificate with Thumbprint $Thumbprint"
        $PSBoundParameters.Remove('Thumbprint') | out-Null
        Import-PrivateCertificate @PSBoundParameters
    }
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Thumbprint,

		[System.String]
		$Path,

		[System.String]
		$Password
	)
    
	$TestResults = $true
    
    $Cert = Get-ChildItem Cert:\LocalMachine\my\$Thumbprint -ErrorAction SilentlyContinue
    if([string]::IsNullOrEmpty($Cert)){
        $TestResults = $false
    }
    Write-Output $TestResults
}


Export-ModuleMember -Function *-TargetResource

