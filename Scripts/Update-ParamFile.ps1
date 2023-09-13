#---------------------------------------------------------------------------------------------------------
#	<copyright file="Update-ParamFile.ps1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------<#
<#
    .SYNOPSIS
        Updates a Parameter file and replaces tokens with values from the source variables yaml file.

    .PARAMETER Parameter File Name
        Full path to file containing the references to be replace and the new values

    .PARAMETER Variables File Name
        Full path location to file containing the source variables  
        
    .PARAMETER KvVersionKey
        The version of the Keyvault Secret
#>

[CmdletBinding()]
param 
(
    [Parameter(Mandatory)]
    $ParametersFile,

    [Parameter(Mandatory)]
    $VariablesFile
)


# ECHO OUT THE INPUTS PROVIDED
Write-Host "PSScriptRoot == $($PSScriptRoot)"
Write-Host "ParametersFile == $ParametersFile"
Write-Host "VariablesFile == $VariablesFile"

# GET VALUES TO USE FROM VARIABLES FILE

# VERIFY THE VARIABLES FILE CAN BE LOCATED
if (!(Test-Path -Path $VariablesFile)){
    Write-Host "The specified variables file $VariablesFile could not be located."
    return 1
}

# GET HASHTABLE OF ALL VARIABLES
# DETERMINE IF VARIABLE FILE IS FROM ADO OR GITHUB
if ($VariablesFile.Contains(".env")){
    $allVariables = &$PSScriptRoot\Get-AllGhVariables.ps1 -VariablesFile $VariablesFile 
} else {
    $allVariables = &$PSScriptRoot\Get-AllAdoVariables.ps1 -VariablesFile $VariablesFile
}

if ($null -eq $allVariables){
    Write-Host "Variables hashtable was not loaded correctly.  Exiting"
    return $null
}

# VERIFY WE CAN GET PARAMETERS FILE
if (!(Test-Path -Path $ParametersFile)){
    Write-Host "The specified parameters file $ParametersFile could not be located."
    return 1
}

[bool] $bHasChanged = $false
$content = Get-Content -Path $ParametersFile -RAW

foreach ($t in $allVariables.Keys){
    $token = "[[$t]]"
    
    if($content.Contains($token)){
        Write-Host "$($token) == $($allVariables[$t])"
        $content = $content.Replace($token, $allVariables[$t])
        $bHasChanged = $true
    }
}

if ($null -ne $KvVersionKey){
    $content = $content.Replace("[[KvVersionKey]]", $KvVersionKey)
}

if ($bHasChanged){
    try{
        Out-File -FilePath $ParametersFile -InputObject $content -Force
        Write-Host "Updated parameters file successfully written to the file system."
    }
    catch{
        Write-Host "There was an error writing the new params file out to the file sytem."
        return
    }
}

Write-Host "Parameters file successfully updated."