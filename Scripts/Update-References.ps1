#---------------------------------------------------------------------------------------------------------
#	<copyright file="Update-References.ps1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------
<#
    .SYNOPSIS
        Searches the ARM and parameter files for the project and updates references to match the current deployment.

    .PARAMETER ReferenceListFile
        File containing the references to be replace and the new values
#>

# [CmdletBinding()]
# param 
# (
#     [Parameter(Mandatory)]
#     $ReferenceListFile
# )


# WHEN SET TO TRUE, GENERIC TAGS WILL BE PLACED INTO ARMS AND PARAM FILES
#
[bool]$bUseTagValues = $true

Write-Host "TenantId == $tenantId"
Write-Host "Environment == $env"
Write-Host "Region == $region"
Write-Host "AppName == $appName"
Write-Host "TargetResourceGroup == $targetRg"


# GET COLLECTION OF ALL FILES TO UPDATE
$d = Get-ChildItem -Recurse ../ARM/*.json
$p = Get-ChildItem -Recurse ../Parameters/*.json
$FileList = $d + $p

# GET TEXT TO REPLACE AND VALUES
# $ReplacementList = @{
#     '279e38ad-9350-46e1-9dcb-b7d5ce07de49' = '[[SubscriptionId]]';
#     '8629be3b-96bc-482d-a04b-ffff597c65a2' = '[[SubscriptionId]]';
#     $tenantId = '[[TenantId]]';
#     $targetRg = '[[TargetResourceGroup]]';
#     'dependencies-rg' =  '[[TargetResourceGroup]]';
#     'CoreInfrastructure' = '[[TargetResourceGroup]]';
# }

# REPLACE VALUES WITH TAGS
$ListTags = @{
    $subscriptionId = '[[SubscriptionId]]';
    $tenantId = '[[TenantId]]';
    $targetRg = '[[TargetResourceGroup]]';
}

# REPLACE TAGS WITH VALUES FROM RING0 VARIABLES FILE
$env = .\Get-VariableValue -VariablesFile ..\Variables-Ring0.yml -VariableName "Env"
$appName = .\Get-VariableValue -VariablesFile ..\Variables-Ring0.yml -VariableName "AppName"
$instance = .\Get-VariableValue -VariablesFile ..\Variables-Ring0.yml -VariableName "InstanceNumber"
$targetRg = "rg-$($appName)-$($env)-$($instance)"

$ListRing0 = @{
    '[[SubscriptionId]]' = (.\Get-VariableValue -VariablesFile ..\Variables-Ring0.yml -VariableName "SubscriptionId");
    '[[TenantId]]' = (.\Get-VariableValue -VariablesFile ..\Variables-Ring0.yml -VariableName "TenantId");
    '[[TargetResourceGroup]]' = $targetRg;
}

# REPLACE TAGS WITH VALUES FROM RING1 VARIABLES FILE
$env = .\Get-VariableValue -VariablesFile ..\Variables-Ring1.yml -VariableName "Env"
$appName = .\Get-VariableValue -VariablesFile ..\Variables-Ring1.yml -VariableName "AppName"
$instance = .\Get-VariableValue -VariablesFile ..\Variables-Ring1.yml -VariableName "InstanceNumber"
$targetRg = "rg-$($appName)-$($env)-$($instance)"

$ListRing1 = @{
    '[[SubscriptionId]]' = (.\Get-VariableValue -VariablesFile ..\Variables-Ring1.yml -VariableName "SubscriptionId");
    '[[TenantId]]' = (.\Get-VariableValue -VariablesFile ..\Variables-Ring1.yml -VariableName "TenantId");
    '[[TargetResourceGroup]]' = $targetRg;
}

foreach ($file in $FileList){

    [bool]$bHasChanged = $false
    $content = Get-Content -Path $file.FullName -Raw
    
    # DEFAULT IS TO USE RING0 UNLESS RING 1 OR TAGS IS SPECIFIED
    $ReplacementList = $ListRing0

    if ($file.Name.Contains("Ring1")){
        $ReplacementList = $ListRing1
    }

    if ($bUseTagValues){
        $ReplacementList = $ListTags
    }
    
    foreach($o in $ReplacementList.GetEnumerator())
    {
        if ($content.Contains($o.Key)){
            $content = $content.Replace($o.Key, $o.Value)
            $bHasChanged = $true
        }
    }

    if ($bHasChanged){
        Out-File -FilePath $file.FullName -InputObject $content -Force
    }
}