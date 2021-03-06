#region Private Functions

function Test-XmlForm([string]$Path)
{
    [bool](New-Variable -Name isWellFormedXml -Value $false) | Out-Null

    if (Test-Path -Path $Path)
    {
        try
        {
            [System.Xml.XmlDocument]$xmlFile = Get-Content $Path
            $isWellFormedXml = $true
        }
        catch
        {
            $isWellFormedXml = $false
        }
    }   

    return $isWellFormedXml
}

#endregion



function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param (        
        [Parameter(Mandatory=$true,Position=0)][String]$SourceDirectory,
        [Parameter(Mandatory=$true,Position=1)][String]$DestinationDirectory
    )
    $returnValue = @{}
    $returnValue.Add("SourceDirectory", $SourceDirectory)
    $returnValue.Add("DestinationDirectory", $DestinationDirectory)
    return $returnValue

}

function Set-TargetResource
{
    [CmdletBinding()]    
    Param (
        [Parameter(Mandatory=$true,Position=0)][String]$SourceDirectory,
        [Parameter(Mandatory=$true,Position=1)][String]$DestinationDirectory             
    )
    [bool]$xmlFilesAreWellFormed = $false
    $configFiles = Get-ChildItem -Path $DestinationDirectory\* -Include *.xml, *.config
    foreach ($configFile in $configFiles)
    {
        $fileName = $configFile.Name
        $filePath = $configFile.FullName
        [bool]$xmlIsWellFormed = Test-XmlForm -Path $filePath
        if (!($xmlIsWellFormed))
        {
            $sourceFilePath = Join-Path -Path $SourceDirectory -ChildPath $fileName
            $destinationFilePath = $filePath
            Copy-Item -Path $sourceFilePath -Destination $destinationFilePath
        }
    }    
}

function Test-TargetResource
{   
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory=$true,Position=0)][String]$SourceDirectory,
        [Parameter(Mandatory=$true,Position=1)][String]$DestinationDirectory      
    )
    [bool]$xmlFilesAreWellFormed = $false
    $configFiles = Get-ChildItem -Path $DestinationDirectory\* -Include *.xml, *.config
    foreach ($configFile in $configFiles)
    {
        $filePath = $configFile.FullName
        [bool]$xmlIsWellFormed = Test-XmlForm -Path $filePath
        if (!($xmlIsWellFormed))
        {
            return $false
        }
    }
    $xmlFilesAreWellFormed = $true
    return $xmlFilesAreWellFormed
}

Export-ModuleMember -Function *-TargetResource 
