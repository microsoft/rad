#---------------------------------------------------------------------------------------------------------
#	<copyright file="Update-TemplateText.ps1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------
<#
    .SYNOPSIS
        Replaces words in the replacement list with values in the provided files.

    .PARAMETER FileList
        List of files to replace words in

    .PARAMETER ReplacementList
        Hashtable of key words and new values
#>

[CmdletBinding()]
param 
(
    [Parameter(Mandatory)]
    [string[]]
    $FileList,

    [Parameter(Mandatory)]
    $ReplacementList
)

foreach($file in $FileList)
{
    Write-Host "PSScriptRoot == $($PSScriptRoot)"
    $fullPath = "$PSScriptRoot\..\$file"
    Write-Host "Full content path == $($fullPath)"
    $content = Get-Content -Path $fullPath -Raw
    
    foreach($replacementText in $ReplacementList.GetEnumerator())
    {
        $content = $content.Replace($replacementText.Name, "$($replacementText.Value)")
    }

    Out-File -FilePath $fullPath -InputObject $content -Force
}
