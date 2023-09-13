#---------------------------------------------------------------------------------------------------------
#	<copyright file="Bootstrap.ps1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------

<#
.SYNOPSIS
    A simple script that:
    Creates a new service principal used by Azure DevOps service connector
    Creates a new service connector used by Azure DevOps service connector
    Creates a new role assignmet in the provided Azure subscription
    Creates a new Azure key vault
    Creates a new set of secrets required by Azure DevOps pipeline using the service principal created by this process

.DESCRIPTION
    This script will deploy resources required to run pipelines in Azure DevOps for Leading Edge Delivery.
    Scope can be resource group or subscription for role assignment.


.PARAMETER AzureDevOpsPAT
    AzureDevOps user defined PAT token utilized during the operation of this script.

.PARAMETER OrganizationName
    Organization name used in Azure DevOps.
    Example: "Contoso"

.PARAMETER ProjectName
    AzureDevOps Project Name.
    Example: Contoso

.PARAMETER Scope
    Scope defined for Azure Role Assignment.
    Example: "ResourceGroup | Subscription"

.PARAMETER AzureRoleDefinitionName
    Role definition used during role assignment of service principal.
    Example: "Owner"

.PARAMETER AzureKeyVaultRoleDefinitionName
    RBAC role definition used during role assignment of service principal for RBAC enabled Key Vault.
    Example: "Key Vault Secrets Officer"

.PARAMETER VariablesFile
    Path to the Yaml file containing the variables for the target ring deployment.
    Example: '..\.ado\Template\Variable\Variables-Ring0.yml

.PARAMETER useCertAuth
    Switch to supply a certifcate for Service Principal Auth

.PARAMETER ExportAdoAgentCredentials
    Switch used to allow encrypted credentials for the AdoAgent to be exported.

.PARAMETER MaxAgentPoolCapacity
    Determines the maximum number of agents in the Azure DevOps pool

.PARAMETER IdleAgentPoolCapacity
    Determines the minimum number of agents in the Azure DevOps pool that are always idle

.EXAMPLE
    Default Bootstrap:
    .\Bootstrap.ps1 -VariablesFile '..\.ado\Template\Variable\Variables-Ring0.yml' -AzureDevOpsPAT '{YourPAT}' `
        -OrganizationName '{YourOrgName}' -ProjectName '{YourProjectName}' `
        -OrganizationUrl 'dev.azure.com' -Scope 'Subscription' `
        -CloudEnv 'AzureCloud' -useSelfSignedCertificate
        
.NOTES
    Requires the following modules:
    Az - https://docs.microsoft.com/en-us/powershell/azure/?view=azps-6.4.0
    Az.KeyVaults - https://docs.microsoft.com/en-us/powershell/module/az.keyvault/?view=azps-6.4.0
    Az.Resources - https://docs.microsoft.com/en-us/powershell/module/az.resources/?view=azps-6.4.0
    Az CLI - https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
#>

[CmdletBinding()]
param (
    # Variables file from the repo that will be used as the source for all variable values
    # Example: Variables-Ring0.yml
    [Parameter(Mandatory)]
    [string] $VariablesFile,

    # AzureDevOps user defined PAT token utilized during the operation of this script
    # Example: "YOURPATFROMDEVOPS"
    [Parameter(mandatory = $false)]
    [string]
    $AzureDevOpsPAT,
    
    # Repository URL where pipeline is maintained
    [Parameter(Mandatory = $false)]
    [string]
    $RepoUrl,

    # Switch used to supply Certificate Based Authentificate for Service Principals
    [Parameter(Mandatory = $false)]
    [switch]
    $useCertAuth,

    # Scope defined for Azure Role Assignment
    # Example: "ResourceGroup | Subscription"
    [Parameter(mandatory = $false)]
    [string]
    $Scope = "Subscription",

    # Role definition used during role assignment of service principal
    # Example: "Owner"
    [Parameter(mandatory = $false)]
    [string]
    $AzureRoleDefinitionName = "Owner",

    # RBAC role definition used during role assignment of service principal for RBAC enabled Key Vault
    # Example: "Key Vault Secrets Officer"
    [Parameter(mandatory = $false)]
    [string]
    $AzureKeyVaultRoleDefinitionName = "Key Vault Administrator",

    # Switch used to allow encrypted credentials for the AdoAgent to be exported.
    [switch]$ExportAdoAgentCredentials,

    # Determines the maximum number of agents in the Azure DevOps pool
    [Parameter(Mandatory = $false)]
    [int]$MaxAgentPoolCapacity = 3,

    # Determines the minimum number of agents in the Azure DevOps pool that are always idle
    [Parameter(Mandatory = $false)]
    [int]$IdleAgentPoolCapacity = 0

)

# RELOAD COMMON MODULES FILE TO GET LATEST
$modules = Get-Module
foreach ($_ in $modules) {
    if ($_.Name -eq "BaseCommon") {
        Remove-Module -Name "BaseCommon" -Force
    }
}

Import-Module .\BaseCommon.psm1

$ErrorActionPreference = 'Stop'
$WarningPreference = "SilentlyContinue"
# Suppress warnings that are throwned when using the Az PowerShell modules
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

# GET VARIABLES FROM SPECIFIED VARIABLES FILE
#
Unblock-File -Path .\Get-VariableValue.ps1

$vars = .\Get-AllAdoVariables -VariablesFile $VariablesFile

###################################################################################
# CONFIRM DEPLOY
###################################################################################
Write-Host "" 
Write-Host "The following deployment will be installed: " -ForegroundColor Yellow
Write-Host "`tDeployment Type:  Azure DevOps" -ForegroundColor Yellow
Write-Host "`tTarget Resource Group == $($vars['TargetResourceGroupCore']) " -ForegroundColor Yellow
Write-Host "`tTarget Region == $($vars['TargetRegion']) " -ForegroundColor Yellow
Write-Host "`tTenantId == $($vars['TenantId']) " -ForegroundColor Yellow
Write-Host "`tSubscriptionId == $($vars['SubscriptionId']) " -ForegroundColor Yellow
Write-Host "`tService Principal Id == $($vars['AdoServicePrincipalId']) " -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host 'Please enter "Y" or "y" to continue'

if ($confirm.ToLower() -ne 'y')
{
    return
}

Write-Host "Checking prerequisites ..."
###################################################################################
# CHECK PREREQS
###################################################################################
$null = Get-BootstrapPrerequisites -bootstrapPrerequisitesFile .\bootstrapPrereqs.json -ErrorAction Stop

if ($RepoUrl.Length -eq 0){
    $RepoUrl = $vars["RepoUrl"]
}

# SET PAT ENVIRONMENT VARIABLE FOR AZ DEVOPS EXTENSION
if ($AzureDevOpsPAT.Length -gt 0){
    $ENV:AZURE_DEVOPS_EXT_PAT = $AzureDevOpsPAT
}

if (($useCertAuth) -and ($ENV:PEM_FILEPATH.length -eq 0) ){
    Write-Host "Please set the PEM_FILEPATH environment variable."
    return 0
}

$adoAgentPwdFile = "~/agent$($vars['Env'])$($vars['InstanceNumber']).key"

# AUTHENTICATE WITH SERVICE PRINCIPAL
#
   
if($vars['AdoServicePrincipalId']) {
    Write-Host "Authenticating with Service Princicpal  ..."

    if($useCertAuth) {
        # CHECK FOR THUMBPRINT AS ENVIRONMENT VARIABLE
        if($null -eq $env:CERT_THUMBPRINT){
            $ServicePrincipalCredPrompt = "`tProvide the Certificate Thumbprint for App Registration: $($ServicePrincipalAppId)"
            $CertificateThumbprint = $(Read-Host -Prompt "$($ServicePrincipalCredPrompt)")
        }
        else{
            $CertificateThumbprint = $env:CERT_THUMBPRINT
        }
    }
    else {
        if ($null -eq $env:ClientSecret){
            $ServicePrincipalCredPrompt = "`tProvide the Client Secret for App Registration: $($ServicePrincipalAppId)"
            $ClientSecret = $(Read-Host -Prompt "$($ServicePrincipalCredPrompt)" -MaskInput)
        }
        else{
            $ClientSecret = $env:ClientSecret
        }
    }

    $authenticateWithServicePrincipalParameters = @{
        subscriptionId        = $vars['SubscriptionId']
        tenantId              = $vars['TenantId']
        ServicePrincipalAppId = $vars['AdoServicePrincipalId']
        ClientSecret          = $ClientSecret
        CertificateThumbprint = $CertificateThumbprint
        PemFilePath           = $ENV:PEM_FILEPATH
    }

    $result = Connect-AzServicePrincipal @authenticateWithServicePrincipalParameters
    $Context = Build-AzContextObject $(Get-AzContext)
}
else {
    # AUTHENTICATE USER
    #
    Write-Host "Authenticating user ..."
    $result = Authenticate -subscriptionId $vars['SubscriptionId'] -tenantId $vars['TenantId']
    $Context = Build-AzContextObject $(Get-AzContext)
}

# CREATE RESOURCE GROUP
#
Write-Host "Creating Resource Group $($vars['TargetResourceGroupCore']) ..."
$azureResourceGroup = Get-AzResourceGroup -Name $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue

if ($null -eq $azureResourceGroup) {
    try {
        $azureResourceGroup = New-AzResourceGroup -Name $vars['TargetResourceGroupCore'] -Location $vars['TargetRegion'] -ErrorAction Stop
        Write-Host "`tResource Group $($azureResourceGroup.ResourceGroupName) created"
    } catch {
        Write-Output $Error[0].Exception
        return 1
    }
}
else {
    Write-Host "`tResource Group $($azureResourceGroup.ResourceGroupName) already exists." -ForegroundColor Yellow
}

# CREATE AZURE DEVOPS CONNECTOR TO THE SUBSCRIPTION
#
# SEE IF CONNECTOR ALREADY EXISTS
Write-Host "Checking Azure DevOps Service Connection ..."

$orgUri = "https://dev.azure.com/$($vars['AdoOrganizationName'])/"
$connectors = (az devops service-endpoint list --org $orgUri --project $vars['AdoProjectName']) | ConvertFrom-Json
$connectorExists = $false
foreach ($_ in $connectors){
    if ($_.name -eq $vars['TargetSubscriptionConnection']){
        $connectorExists = $true
        $c = $_
        break
    }
}

$subscription = (az account show | ConvertFrom-Json)
if (!$connectorExists){
    Write-Host "Creating Azure DevOps AzureRM connector '$($vars['TargetSubscriptionConnection'])'."
    if ($useCertAuth){

        if ($null -eq $env:PEM_FILEPATH){
            $ENV:PEM_FILEPATH = $(Read-Host -Prompt "Enter the path to the PEM file.")

            if (!(Test-Path($ENV:PEM_FILEPATH))){
                Write-Host "PEM file not found." -ForegroundColor Red
                return 1
            }
        }
        $c = (az devops service-endpoint azurerm create `
        --name $vars['TargetSubscriptionConnection'] `
        --org $orgUri --project $vars['AdoProjectName'] `
        --azure-rm-subscription-name $subscription.name `
        --azure-rm-service-principal-id $vars['AdoServicePrincipalId'] `
        --azure-rm-subscription-id $subscription.id `
        --azure-rm-tenant-id $vars['TenantId'] `
        --azure-rm-service-principal-certificate-path $env:PEM_FILEPATH ) | ConvertFrom-Json
    }
    else{
        $c = (az devops service-endpoint azurerm create `
            --name $vars['TargetSubscriptionConnection'] `
            --org $orgUri --project $vars['AdoProjectName'] `
            --azure-rm-subscription-name $subscription.name `
            --azure-rm-service-principal-id $vars['AdoServicePrincipalId'] `
            --azure-rm-subscription-id $subscription.id `
            --azure-rm-tenant-id $vars['TenantId'] ) | ConvertFrom-Json
    }
}
else{
    Write-Host "`tConnector $($c.name) already exists." -ForegroundColor Yellow
}

# CREATE SPOKE VIRTUAL NETWORK NSG
#
Write-Host "Checking Network Security Group for Spoke Virtual Network ..."
$nsg = Get-AzNetworkSecurityGroup -Name $vars['NetworkSecurityGroupNameSpoke'] -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue

if ($null -eq $nsg) {
    Write-Host "`tNo Network Security Group found with name '$($vars['NetworkSecurityGroupNameSpoke'])' in resource group '$($vars['TargetResourceGroupCore'])'. Creating a new one ..."
    $result = New-AzResourceGroupDeployment -Name "deploySpokeNsg" -ResourceGroupName $vars['TargetResourceGroupCore'] -TemplateFile ../ARM/NetworkSecurityGroups/deploy.json -TemplateParameterFile ../Parameters/NetworkSecurityGroups/parameters.json -networkSecurityGroupName $vars['NetworkSecurityGroupNameSpoke']
    Write-Host "`tNetwork Security Group '$($vars['NetworkSecurityGroupNameSpoke'])' created successfully."
} 
else {
    Write-Host "`tNetwork Security Group '$($vars['NetworkSecurityGroupNameSpoke'])' already exists." -ForegroundColor Yellow
}

# CREATE APP GATEWAY NETWORK NSG
#

$nsgAppGwName = "nsg-AppGw-$($vars['AppName'])-$($vars['InstanceNumber'])"
Write-Host "Checking Network Security Group for Application Gateway ..."
$nsg = Get-AzNetworkSecurityGroup -Name $nsgAppGwName -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue

if ($null -eq $nsg) {
    Write-Host "`tNo Network Security Group found with name '$($nsgAppGwName)' in resource group '$($vars['TargetResourceGroupCore'])'. Creating a new one ..."
    $result = New-AzResourceGroupDeployment -Name "deploySpokeNsg" -ResourceGroupName $vars['TargetResourceGroupCore'] -TemplateFile ../ARM/NetworkSecurityGroups/deploy.json -TemplateParameterFile ../Parameters/NetworkSecurityGroups/parametersAppGw.json -networkSecurityGroupName $nsgAppGwName
    Write-Host "`tNetwork Security Group '$($nsgAppGwName)' created successfully."
} else {
    Write-Host "`tNetwork Security Group '$nsgAppGwName' already exists." -ForegroundColor Yellow
}

# CREATE SPOKE VIRTUAL NETWORK
#
Write-Host "Checking Spoke Virtual Network ..."
$vnet = Get-AzVirtualNetwork -Name $vars['SpokeVnetName'] -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue

if ($null -eq $vnet) {
    Write-Host "`tNo Virtual Network found with name '$($vars['SpokeVnetName'])' in resource group '$($vars['TargetResourceGroupCore'])'. Creating a new one ..."

    # UPDATE ADO PARAMETERS FILE
    Write-Host "`tUpdating Spoke Virtual Network parameters file."
    Copy-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke.json ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
    ./Update-ParamFile.ps1 -ParametersFile ..\Parameters\VirtualNetwork\parametersSpoke-temp.json -VariablesFile ..\.ado\Template\Variable\Variables-$($vars['Env']).yml

    $result = New-AzResourceGroupDeployment -Name "deploySpokeVnet" -ResourceGroupName $vars['TargetResourceGroupCore'] -TemplateFile ../ARM/VirtualNetwork/deploy.json -TemplateParameterFile ../Parameters/VirtualNetwork/parametersSpoke-temp.json -vnetName $vars['SpokeVnetName']
    Remove-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
    Write-Host "`tSpoke Virtual Network created successfully."
} else {
    Write-Host "`tVirtual network '$($vars['SpokeVnetName'])' already exists." -ForegroundColor Yellow
    Write-Host "`tChecking if Network Security Group '$($vars['NetworkSecurityGroupNameSpoke'])' is applied to the virtual network '$($vars['SpokeVnetName'])'."

    $vnet = Get-AzVirtualNetwork -Name $vars['SpokeVnetName'] -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue
    $bNsgAttached = $false

    foreach ($_ in $vnet.Subnets) {
        if ($null -ne $_.NetworkSecurityGroup) {
            $bNsgAttached = $true
            break
        }
    }

    if (-not $bNsgAttached) {

        Write-Host "`tAttaching Network Security Group '$($vars['NetworkSecurityGroupNameSpoke'])' to virtual network '$($vars['SpokeVnetName'])'."

        # UPDATE ADO PARAMETERS FILE
        Write-Host "`tUpdating Spoke VNet Parameters file."
        Copy-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke.json ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
        ./Update-ParamFile.ps1 -ParametersFile ..\Parameters\VirtualNetwork\parametersSpoke-temp.json -VariablesFile ..\.ado\Template\Variable\Variables-$($vars['Env']).yml

        $result = $null
        $newAzResourceGroupDeploymentParameters = @{
            Name                  = 'deploySpokeVnet'
            ResourceGroupName     = $vars['TargetResourceGroupCore']
            vnetName              = $vars['SpokeVnetName']
            TemplateFile          = '../ARM/VirtualNetwork/deploy.json'
            TemplateParameterFile = '../Parameters/VirtualNetwork/parametersSpoke-temp.json'
        }
        $result = New-AzResourceGroupDeployment @newAzResourceGroupDeploymentParameters
        Remove-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
    } else {
        Write-Host "`tNetwork Security Group '$($vars['NetworkSecurityGroupNameSpoke'])' is already attached to virtual network '$($vars['SpokeVnetName'])'." -ForegroundColor Yellow
    }

    # CHECK THAT NSG WAS SUCCESSFULLY APPLIED
    $vnet = Get-AzVirtualNetwork -Name $vars['SpokeVnetName'] -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue
    $bNsgAttached = $false

    foreach ($_ in $vnet.Subnets) {
        if ($null -ne $_.NetworkSecurityGroup) {
            $bNsgAttached = $true
            break
        }
    }

    if (-not $bNsgAttached) {
        Write-Host "Network Security Group '$($vars['NetworkSecurityGroupNameSpoke'])' was not attached.  Exiting." -ForegroundColor Red
        Exit 1
    }
}

# CREATE KEY VAULT
#
Write-Host "Checking Key Vault ..."
$vault = Get-AzKeyVault -VaultName $vars['KeyVaultName'] -ResourceGroupName $vars['TargetResourceGroupCore']

# IF VAULT DOESN'T EXIST, CREATE A NEW VAULT AND ASSIGN RBAC
if ($null -eq $vault) {
    try {
        Write-Host "`tCreating Key Vault '$($vars['KeyVaultName'])'."
        $vault = New-AzKeyVault -Name $vars['KeyVaultName'] -ResourceGroupName $vars['TargetResourceGroupCore'] -location $vars['TargetRegion'] -SoftDeleteRetentionInDays 7 -EnabledForTemplateDeployment -EnableRbacAuthorization -EnabledForDiskEncryption -ErrorAction Stop
        Write-Host "`tKey Vault '$($vars['KeyVaultName'])' created successfully."
    } catch {
        Write-Host "`tCouldn't create Key Vault with name '$($vars['KeyVaultName'])'. Error - $($Error[0].Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "`tKey Vault $($vault.VaultName) already exists." -ForegroundColor Yellow
}

# Creating RBAC permissions at defined scope and role definition
switch ( $Scope ) {
    ResourceGroup { $assignmentScope = "/subscriptions/$($context.Subscription.Id)/resourcegroups/$($vars['TargetResourceGroupCore'])" }
    Subscription { $assignmentScope = "/subscriptions/$($context.Subscription.Id)" }
}

# SET KEY VAULT ROLE ASSIGNMENT FOR SPN
Write-Host "`tSetting Key Vault role assignment '$AzureKeyVaultRoleDefinitionName' to Service Principal '$($vars['AdoServicePrincipalId'])'."
$assign = Set-KeyVaultRoleAssignment -ServicePrincipalObject $vars['AdoServicePrincipalObjectId'] -AzureKeyVaultRoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $assignmentScope

if (($null -ne $assign) -and ($assign.count -eq 2) -and ($assign[1] -ne 0)){
    Write-Host "`tThe KeyVault role assignment did not complete successfully.  Please ensure the correct Service Principal ObjectId has been provided for the application registration. " -ForegroundColor Red
    exit 1
}
# USE TEST SECRET WRITE TO VERIFY PERMISSIONS HAVE REPLICATED
#
Write-Host "Verifying Keyvault configuration..."
[bool]$bContinue = $true
[int]$maxCount = 20
[int]$count = 0
while ($bContinue){
    Write-Host "." -NoNewline
    $result = Set-AzKeyVaultSecret -VaultName $vars['KeyVaultName'] -Name TestSecret -SecretValue (ConvertTo-SecureString (Get-StringRandom) -AsPlainText -Force) -Expires (Get-Date).AddYears($DurationYears) -ErrorAction SilentlyContinue
    $null = Remove-AzKeyVaultSecret -VaultName $vars['KeyVaultName'] -Name TestSecret -Force -ErrorAction SilentlyContinue
    $null = Remove-AzKeyVaultSecret -VaultName $vars['KeyVaultName'] -Name TestSecret -Force -InRemovedState -ErrorAction SilentlyContinue

    if (($null -ne $result) -and ($result.Name -eq "TestSecret")){
        $bContinue = $false
    }

    # BREAK OUT OF WHILE LOOP IF WE EXCEED THE MAX RETRIES
    $count++
    if ($count -gt $maxCount){
        Write-Host "The maximum number of retries while waiting on Keyvault has been exceeded." -ForegroundColor Red
        exit 1
    }

    if ($bContinue){
        Start-Sleep 15
    }
}
Write-Host "Keyvault configuration verified."

# CREATE SECRETS IN KEY VAULT
#
Write-Host "Checking secrets in Key Vault ..."

# ADD ADO AGENT PASSWORD
$password = Get-StringRandom
$securesecret = New-Password $password
$value = ConvertTo-SecureString $securesecret -AsPlainText -Force
$result = Set-AzKeyVaultSecret -VaultName $vars['KeyVaultName'] -Name "adoAgentPassword" -SecretValue $value -Expires (Get-Date).AddYears($DurationYears)

if ($ExportAdoAgentPwd -eq $true){
    $null = $securesecret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $adoAgentPwdFile -Force
}

# CREATE AZURE DEVOPS SCALE SET
#
Write-Host "Checking Azure DevOps Virtual Machine Scale Set."
$vSTSAccountName = "https://dev.azure.com/$($vars['AdoOrganizationName'])"
$teamProject = $vars['AdoProjectName']
# THIS VMSS NAME IS USED IN THE PREREQS CHECK.  IF CHANGED, UPDATE PREREQS ALSO
$vmssName = "ado-$($vars['AppName'])-$($vars['InstanceNumber'])"
Write-Host "`tSearching for a Virtual Machine Scale Set name '$vmssName' in resource group '$($vars['TargetResourceGroupCore'])'."
$result = Get-AzVmss -VMScaleSetName $vmssName -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue

if ($null -eq $result) {
    Write-Host "`tNo Virtual Machine Scale Set with name '$vmssName' was found in resource group '$($vars['TargetResourceGroupCore'])'."
    # UPDATE ADO PARAMETERS FILE
    Write-Host "`tUpdating Virtual Machine Scale Set parameters file."
    Copy-Item -Path ..\Parameters\VirtualMachineScaleSets\ado.parameters.json ..\Parameters\VirtualMachineScaleSets\ado.parameters-temp.json
    ./Update-ParamFile.ps1 -ParametersFile ..\Parameters\VirtualMachineScaleSets\ado.parameters-temp.json -VariablesFile ..\.ado\Template\Variable\Variables-$($vars['Env']).yml

    $content = Get-Content -Path ./ConfigureAdo.sh -AsByteStream
    $linuxConfigScript = [convert]::ToBase64String($content)

    $secret = Get-AzKeyVaultSecret -VaultName $vars['KeyVaultName'] -Name "adoAgentPassword" -AsPlainText -ErrorAction SilentlyContinue | ConvertTo-SecureString -AsPlainText -Force

    if (-not $secret) {
        Write-Host "`tNo secret with name 'adoAgentPassword' was found in Key Vault $($vars['KeyVaultName'])." -ForegroundColor Red
        exit 1
    }

    Write-Host "`tDeploying Virtual Machine Scale Set '$vmssName' in resource group '$($vars['TargetResourceGroupCore'])'."
    $newAzResourceGroupDeploymentParameters = @{
        Name                  = 'deployAdoVmss'
        vmssName              = $vmssName
        ResourceGroupName     = $vars['TargetResourceGroupCore']
        teamProject           = $teamProject
        adminPassword         = $secret
        VSTSAccountName       = $vSTSAccountName
        PATToken              = $AzureDevOpsPAT
        deploymentGroup       = $vars['DeploymentGroupName']
        linuxBase64Script     = $linuxConfigScript
        instanceSize          = "Standard_D3_v2"
        TemplateFile          = '../ARM/VirtualMachineScaleSets/deploy.json'
        TemplateParameterFile = '../Parameters/VirtualMachineScaleSets/ado.parameters-temp.json'
    }
    $result = New-AzResourceGroupDeployment @newAzResourceGroupDeploymentParameters

    Remove-Item ..\Parameters\VirtualMachineScaleSets\ado.parameters-temp.json
    Write-Host "`tAzure DevOp Virtual Machine Scale Set 'ado-$vmssName' created."
} else {
    Write-Host "`tVirtual Machine Scale Set '$($vmssName)' already exists." -ForegroundColor Yellow
}

# CREATE AZURE DEVEOPS POOL
Write-Host "Checking ADO Agent Pool '$($vars['DeploymentGroupName'])'."

$getAzDevOpsPoolParameters = @{
    OrgUrl               = "dev.azure.com"
    OrgName              = $vars['AdoOrganizationName']
    PAT                  = $ENV:AZURE_DEVOPS_EXT_PAT
    PoolName             = $vars['DeploymentGroupName']
}

$pool = Get-AzDevOpsPool @getAzDevOpsPoolParameters
$vmss = Get-AzVmss -VMScaleSetName $vmssName -ResourceGroupName $vars['TargetResourceGroupCore'] -ErrorAction SilentlyContinue

# CHECK IF AZURE DEVOPS POOL EXISTS
if($null -ne $pool) {
    Write-Host "`t$($vars['DeploymentGroupName']) is already an existing pool" -ForegroundColor Yellow
}
else {
    $ProjectGuid = Get-AdoProjectGuid -OrgUrl "dev.azure.com" -OrgName $vars['AdoOrganizationName'] -ProjectName $vars['AdoProjectName'] -PAT $ENV:AZURE_DEVOPS_EXT_PAT

    $addAzDevOpsPoolParameters = @{
        PAT                  = $ENV:AZURE_DEVOPS_EXT_PAT
        OrgUrl               = "dev.azure.com"
        OrgName              = $vars['AdoOrganizationName']
        PoolName             = $vars['DeploymentGroupName']
        ProjectGuid          = $ProjectGuid
        ServiceConnectorName = $vars['TargetSubscriptionConnection']
        SubscriptionId       = $vars['SubscriptionId']
        rgName               = $vars['TargetResourceGroupCore']
        VMSSName             = $vmss.Name
        MaxCapacity          = $MaxAgentPoolCapacity
        IdleCapacity         = $IdleAgentPoolCapacity
    }
    Write-Host "`tChecking ADO Agent Pool '$($vars['DeploymentGroupName'])'."
    $result = Add-AzDevOpsPool @addAzDevOpsPoolParameters

    if ($result -ne 0) {
        Write-Host "The configuration of the Azure DevOps Agent Pool failed. Exiting" -ForegroundColor Red
        exit 1
    }
}

# CREATE STARTING PIPELINE

if ($null -ne $RepoUrl){
    $adoUrl = "https://dev.azure.com/$($vars['AdoOrganizationName'])/"
    $p = (az pipelines show --name $vars['PipelineName'] --org $adoUrl --project $vars['AdoProjectName'] 2>$null) | ConvertFrom-Json
    
    if ($null -eq $p){
        Write-Host "Creating Azure Pipeline '$($vars['PipelineName'])'."
        $p = (az pipelines create --name $vars['PipelineName'] --branch $vars['BranchName'] --org $adoUrl --project $vars['AdoProjectName'] --repository $RepoUrl --yml-path "/.ado/Template/PipelineMain.yml" --service-connection $vars['DeploymentGroupName'] --skip-first-run) | ConvertFrom-Json
        # Example for adding a pipeline variable
        # $null = (az pipelines variable create --name subscriptionId --allow-override false --org $adoUrl --project $adoProject --pipeline-id $p.id --secret $false --value $subscriptionId)
    }
    else{
        Write-Host "Pipeline $($p.name) already exists."
    }
    
}

Write-Host "Disconnecting $($vars['AdoServicePrincipalId'])."
$null = Disconnect-AzAccount

# REMOVE CACHED SPN DATA
if (!$ExportAdoAgentCredentials){
    $result = Remove-Item -Path $adoAgentPwdFile -Force -ErrorAction SilentlyContinue
}
$result = Clear-AzContext -Force
$secret = $null
$AzureDevOpsPAT = $null
$ClientSecret = $null
$content = $null
$vault = $null
Write-Host "Bootstrap process completed!" -ForegroundColor Green