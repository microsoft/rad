<#
.SYNOPSIS

.DESCRIPTION
    This script will deploy resources required to run pipelines in Azure DevOps for Leading Edge Delivery.
    Scope can be resource group or subscription for role assignment.
    
.PARAMETER AzureRoleDefinitionName
    Role definition used during role assignment of service principal.
    Example: "Owner"

.PARAMETER AzureKeyVaultRoleDefinitionName
    RBAC role definition used during role assignment of service principal for RBAC enabled Key Vault.
    Example: "Key Vault Secrets Officer"
    
.PARAMETER LocalCertificatePolicyPath
    Local path of certificate policy json file
    Example: "C:\git\led\LeadingEdgeDelivery\Certificates\cert_policy.json"

.PARAMETER AksCertName
    Aks Certificate Name
    Example: "AksCert"

.PARAMETER Scope
    Scope defined for Azure Role Assignment.
    Example: "ResourceGroup | Subscription"

.PARAMETER VariablesFile
    Path to the Env file containing the variables for the target ring deployment.
    Example: '..\.github\Variables\Variables-Ring0.env

.PARAMETER CloudEnv
    The target Azure Cloud environment where the solution will be deployed.
    Example: AzureCloud

.PARAMETER useSelfSignedCertificate
    Switch to supply a self signed certificate for sample applications

.PARAMETER sshKeyFile
    SSH Public Key file used for agent authentication.
    Example: "~\.ssh\id_rsa"

.PARAMETER ExportJumpboxCredentials
    Switch used to allow encrypted credentials for the GitHub Runner agent to be exported.

.PARAMETER useServicePrincipalCertificate
    Switch to supply a certifcate for Service Principal Auth
    
.EXAMPLE
    Default Bootstrap:
    .\Bootstrap-Github.ps1 -VariablesFile '..\.github\Variables\Variables-Ring0.env' `
        -Scope 'Subscription' -CloudEnv 'AzureCloud' -useSelfSignedCertificate -useServicePrincipalCertificate
       
.NOTES
    Requires the following modules:
    Az - https://docs.microsoft.com/en-us/powershell/azure/?view=azps-6.4.0
    Az.KeyVaults - https://docs.microsoft.com/en-us/powershell/module/az.keyvault/?view=azps-6.4.0
    Az.Resources - https://docs.microsoft.com/en-us/powershell/module/az.resources/?view=azps-6.4.0
    Az CLI - https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
#>

[CmdletBinding()]
param (
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

    # # Local path of certificate policy json file
    # # Example: "C:\git\led\LeadingEdgeDelivery\Certificates"
    # [Parameter(
    #     Mandatory = $false)]
    # [string]
    # $LocalCertificatePolicyPath = "$PSScriptRoot\..\Certificates\cert_policy.json",

    # # Aks Certificate Name
    # # Example: "AksCert"
    # [Parameter(mandatory = $false)]
    # [string]
    # $AksCertName = "AksCert",

    # Scope defined for Azure Role Assignment
    # Example: "ResourceGroup | Subscription"
    [Parameter(mandatory = $false)]
    [string]
    $Scope = "Subscription",

    # Variables file from the repo that will be used as the source for all variable values
    # Example: Variables-Ring0.env
    [Parameter(Mandatory)]
    [string] $VariablesFile,

    # Variable used to set the target Azure cloud environment
    # Example: AzureCloud
    [Parameter(Mandatory = $false)]
    [string]$CloudEnv = $null,

    # SSH Public Key file used for agent authentication
    [Parameter(Mandatory = $false)]
    [string]
    $sshKeyFile = $null,

    [Parameter(Mandatory = $false)]
    [boolean]
    $useSelfSignedCertificate = $true,

    # Switch used to allow encrypted credentials for the AdoAgent to be exported.
    [switch] 
    $ExportJumpboxCredentials,

    # Switch used to supply Certificate Based Authentificate for Service Principals
    [switch] 
    $useServicePrincipalCertificate
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

###################################################################################
# GET VARIABLES FROM SPECIFIED VARIABLES FILE
###################################################################################
Write-Host "PSScriptRoot == $($PSScriptRoot)"
Unblock-File -Path $PSScriptRoot\Get-AllGhVariables.ps1

$gh = .\Get-AllGhVariables -VariablesFile $VariablesFile
$ENV = $gh["Env"]
$jumpboxPwdFile = "~/jumpbox$($ENV)$($gh["InstanceNumber"]).key"

###################################################################################
# CONFIRM DEPLOY
###################################################################################
Write-Host "" 
Write-Host "The following deployment will be installed: " -ForegroundColor Yellow
Write-Host "`tDeployment Type:  GITHUB" -ForegroundColor Yellow
Write-Host "`tTarget Resource Group == $($gh['TargetResourceGroupCore']) " -ForegroundColor Yellow
Write-Host "`tTenantId == $($gh['TenantId']) " -ForegroundColor Yellow
Write-Host "`tSubscriptionId == $($gh['SubscriptionId']) " -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host 'Please enter "Y" or "y" to continue'

if ($confirm.ToLower() -ne 'y')
{
    return
}

###################################################################################
# CHECK AZURE ENVIRONMENT
###################################################################################
$environments = Get-AzEnvironment
$environment = $environments | Where-Object { $_.Name -contains $CloudEnv }

if ($null -eq $environment) {
    $environment = $environments | Out-GridView -Title "Please Select an Azure Enviornment." -PassThru
}

if ($null -eq $environment) {
    throw "No Azure Environment targeted"
}
Write-Host "Using Azure environment '$($environment.Name)'."

###################################################################################
# CHECK REQUIRED ENVIRONMENT VARIABLES
# $ENV:GITHUB_PAT
# $ENV:CLIENT_SECRET
#
# IF USING CERT AUTH
# $ENV:PEM_FILEPATH 
# $ENV:CERT_THUMBPRINT 

# APP SECRETS
# $ENV:VOTEWEBAPP_SECRET 
###################################################################################

if (-not $ENV:GITHUB_PAT){
    $i = "`tProvide the GitHub PAT"
    $ENV:GITHUB_PAT = $(Read-Host -Prompt "$($i)" -MaskInput)
}

if($useServicePrincipalCertificate) {
    if (-not $ENV:CERT_THUMBPRINT){
        $ServicePrincipalCredPrompt = "`tProvide the Certificate Thumbprint for App Registration: $($gh["RunnerServicePrincipalId"])"
        $ENV:CERT_THUMBPRINT = $(Read-Host -Prompt "$($ServicePrincipalCredPrompt)")
    }
    if (-not $ENV:PEM_FILEPATH){
        $input = $(Read-Host -Prompt "Please enter the full path to the PEM file")
        if(!(Test-Path($input))) {
            Write-Host "Please set the PEM_FILEPATH environment variable to the file containing the certificate and private key for the service principal $($gh['RunnerServicePrincipalId'])". -ForegroundColor Red
            return 1
        }
    }
} else {
    # USING CLIENT SECRET
    if (-not $ENV:CLIENT_SECRET){
        $ServicePrincipalCredPrompt = "`tProvide the Client Secret for App Registration: $($gh["RunnerServicePrincipalId"])"
        $ENV:CLIENT_SECRET = $(Read-Host -Prompt "$($ServicePrincipalCredPrompt)" -AsSecureString)
    }
}


###################################################################################
# AUTHENTICATE WITH SERVICE PRINCIPAL$gh["RunnerServicePrincipalId"]
###################################################################################
if($gh["RunnerServicePrincipalId"]) {
    Write-Host "Authenticating with Service Princicpal  ..."

    $authenticateWithServicePrincipalParameters = @{
        subscriptionId        = $gh["SubscriptionId"]
        tenantId              = $gh["TenantId"]
        ServicePrincipalAppId = $gh["RunnerServicePrincipalId"]
        ClientSecret          = $ENV:CLIENT_SECRET
        CertificateThumbprint = $ENV:CERT_THUMBPRINT
        PemFilePath           = $ENV:PEM_FILEPATH
    }

    $result = Connect-AzServicePrincipal @authenticateWithServicePrincipalParameters
    $Context = Build-AzContextObject $(Get-AzContext)
}
else {
    # AUTHENTICATE USER
    #
    Write-Host "Authenticating user ..."
    $result = Authenticate -environmentName $($environment.Name) -subscriptionId $gh["SubscriptionId"] -tenantId $gh["TenantId"]
    $Context = Build-AzContextObject $(Get-AzContext)
}

###################################################################################
# CHECK PREREQS
###################################################################################
Write-Host "Checking prerequisites ..."
$checkPrereqsParameters = @{
    resourceGroupName           = $gh["TargetResourceGroupCore"]
    localCertificatePolicyPath  = $LocalCertificatePolicyPath
    jumpBoxName                 = $gh["JumpBoxName"]
    appName                     = $gh["AppName"]
    instanceNumber              = $gh["InstanceNumber"]
    location                    = $gh["TargetRegion"]
    useSelfSignedCertificate    = $useSelfSignedCertificate
    useImportedCertificate      = $true
    # $importedCertificateFilePath = ""
}
# $result = CheckPrereqs @checkPrereqsParameters
# if ($result -ne 0){
#     Write-Host "The prerequisite check failed. Exiting" -ForegroundColor Red
#     exit 1
# }

# $null = Get-BootstrapPrerequisites -bootstrapPrerequisitesFile .\bootstrapPrereqs.json -ErrorAction Stop

###################################################################################
# CREATE RESOURCE GROUP
###################################################################################
Write-Host "Creating Resource Group $($gh["TargetResourceGroupCore"]) ..."
$azureResourceGroup = Get-AzResourceGroup -Name $gh["TargetResourceGroupCore"] -ErrorAction SilentlyContinue

if ($null -eq $azureResourceGroup) {
    try {
        $azureResourceGroup = New-AzResourceGroup -Name $gh["TargetResourceGroupCore"] -Location $gh["TargetRegion"] -ErrorAction Stop
        Write-Host "`tResource Group $($azureResourceGroup.ResourceGroupName) created"
    } catch {
        Write-Output $Error[0].Exception
        return 1
    }
}

else {
    Write-Host "`tResource Group $($azureResourceGroup.ResourceGroupName) already exists." -ForegroundColor Yellow
}

###################################################################################
# CREATE SPOKE VIRTUAL NETWORK NSG
###################################################################################
Write-Host "Checking Network Security Group for Spoke Virtual Network ..."
$nsg = Get-AzNetworkSecurityGroup -Name $gh["NetworkSecurityGroupNameSpoke"] -ResourceGroupName $gh["TargetResourceGroupCore"] -ErrorAction SilentlyContinue

if ($null -eq $nsg) {
    Write-Host "`tNo Network Security Group found with name '$($gh["NetworkSecurityGroupNameSpoke"])' in resource group '$($gh["TargetResourceGroupCore"])'. Creating a new one ..."
    $parameters = @{
        Name                        = "deploySpokeNsg"
        ResourceGroupName           = $gh["TargetResourceGroupCore"]
        TemplateFile                = "../ARM/NetworkSecurityGroups/deploy.json"
        TemplateParameterFile       = "../Parameters/NetworkSecurityGroups/parameters.json"
        NetworkSecurityGroupName    = $gh["NetworkSecurityGroupNameSpoke"]
    }
    $result = New-AzResourceGroupDeployment @parameters

    Write-Host "`tNetwork Security Group '$($gh["NetworkSecurityGroupNameSpoke"])' created successfully."
} else {
    Write-Host "`tNetwork Security Group '$($gh["NetworkSecurityGroupNameSpoke"])' already exists." -ForegroundColor Yellow
}

###################################################################################
# CREATE BASTION NETWORK NSG
###################################################################################
$gh["NetworkSecurityGroupNameBastion"] = "nsg-Bastion-$($gh["AppName"])-$($gh["InstanceNumber"])"
Write-Host "Checking Network Security Group for Bastion ..."
$nsg = Get-AzNetworkSecurityGroup -Name $gh["NetworkSecurityGroupNameBastion"] -ResourceGroupName $gh["TargetResourceGroupCore"] -ErrorAction SilentlyContinue

if ($null -eq $nsg) {
    Write-Host "`tNo Network Security Group found with name '$($gh["NetworkSecurityGroupNameBastion"])' in resource group '$($gh["TargetResourceGroupCore"])'. Creating a new one ..."
    $result = New-AzResourceGroupDeployment -Name "deployBastionNsg" -ResourceGroupName $gh["TargetResourceGroupCore"] -TemplateFile ../ARM/NetworkSecurityGroups/deploy.json -TemplateParameterFile ../Parameters/NetworkSecurityGroups/parametersBastion.json -networkSecurityGroupName $gh["NetworkSecurityGroupNameBastion"]
    Write-Host "`tNetwork Security Group '$($gh["NetworkSecurityGroupNameBastion"])' created successfully."
} else {
    Write-Host "`tNetwork Security Group '$($gh["NetworkSecurityGroupNameBastion"])' already exists." -ForegroundColor Yellow
}

###################################################################################
# CREATE SPOKE VIRTUAL NETWORK
###################################################################################
Write-Host "Checking Spoke Virtual Network ..."
$vnet = Get-AzVirtualNetwork -Name $gh["SpokeVnetName"] -ResourceGroupName $gh["TargetResourceGroupCore"] -ErrorAction SilentlyContinue

if ($null -eq $vnet) {
    Write-Host "`tNo Virtual Network found with name '$($gh["SpokeVnetName"])' in resource group '$($gh["TargetResourceGroupCore"])'. Creating a new one ..."

    try {
        # UPDATE ADO PARAMETERS FILE
        Write-Host "`tUpdating Spoke Virtual Network parameters file."
        Copy-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke.json ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
        ./Update-ParamFile.ps1 -ParametersFile ..\Parameters\VirtualNetwork\parametersSpoke-temp.json -VariablesFile ..\.github\Variables\Variables-$($gh['parameterRingN']).env        
        $result = New-AzResourceGroupDeployment -Name "deploySpokeVnet" -ResourceGroupName $gh['TargetResourceGroupCore'] -TemplateFile ../ARM/VirtualNetwork/deploy.json -TemplateParameterFile ../Parameters/VirtualNetwork/parametersSpoke-temp.json -vnetName $gh['SpokeVnetName']
        Remove-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
        Write-Host "`tSpoke Virtual Network created successfully."
    } catch {
        Remove-Item -Path ..\Parameters\VirtualNetwork\parametersSpoke-temp.json
        Write-Host "`t`t$($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} 

###################################################################################
# CREATE KEY VAULT
###################################################################################
Write-Host "Checking Key Vault ..."
$vault = Get-AzKeyVault -VaultName $gh["KeyVaultName"] -ResourceGroupName $gh["TargetResourceGroupCore"]

# IF VAULT DOESN'T EXIST, CREATE A NEW VAULT AND ASSIGN RBAC
if ($null -eq $vault) {
    try {
        Write-Host "`tCreating Key Vault '$($gh["KeyVaultName"])'."
        $vault = New-AzKeyVault -Name $gh["KeyVaultName"] -ResourceGroupName $gh["TargetResourceGroupCore"] -location $gh["TargetRegion"] -SoftDeleteRetentionInDays 7 -EnabledForTemplateDeployment -EnableRbacAuthorization -EnabledForDiskEncryption -ErrorAction Stop
        Write-Host "`tKey Vault '$($gh["KeyVaultName"])' created successfully."
    } catch {
        Write-Host "`tCouldn't create Key Vault with name '$($gh["KeyVaultName"])'. Error - $($Error[0].Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "`tKey Vault $($vault.VaultName) already exists." -ForegroundColor Yellow
}

###################################################################################
# SET KEY VAULT ROLE ASSIGNMENT FOR SPN
# Creating RBAC permissions at defined scope and role definition
###################################################################################
switch ( $Scope ) {
    ResourceGroup { $assignmentScope = "/subscriptions/$($context.Subscription.Id)/resourcegroups/$($gh["TargetResourceGroupCore"])" }
    Subscription { $assignmentScope = "/subscriptions/$($context.Subscription.Id)" }
}

Write-Host "`tSetting Key Vault role assignment $($AzureKeyVaultRoleDefinitionName) for Service Principal $($gh["RunnerServicePrincipalId"])."

$role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $assignmentScope -ServicePrincipalName $gh["RunnerServicePrincipalId"] 
if ($null -eq $role){
    $role = New-AzRoleAssignment -Scope $assignmentScope -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -ServicePrincipalName $gh["RunnerServicePrincipalId"] -ErrorAction SilentlyContinue
    # Sleep to ensure role assignment is completed
    $maxCount = 60
    $currentCount = 0
    Write-Host "`t`tWaiting for role assignment to propagate." -NoNewLine
    while ($currentCount -lt $maxCount) {
        Start-Sleep 10
        $role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $assignmentScope -ServicePrincipalName $gh["RunnerServicePrincipalId"] 
        if ($null -ne $role) {
            break
        }
        Write-Host "." -NoNewLine
        $currentCount++
    }
    Write-Host "`n`t`tRole assignment complete."
}

###################################################################################
# GRANT GITHUB RUNNER AGENT IDENTITY KEYVAULT SECRET OFFICER AND KEYVAULT CERTIFICATE OFFICER ROLE
###################################################################################
$role = New-AzRoleAssignment -Scope $assignmentScope -RoleDefinitionName "Key Vault Certificates Officer" -ServicePrincipalName $gh["RunnerServicePrincipalId"] -ErrorAction SilentlyContinue
$role = New-AzRoleAssignment -Scope $assignmentScope -RoleDefinitionName "Key Vault Secrets Officer" -ServicePrincipalName $gh["RunnerServicePrincipalId"] -ErrorAction SilentlyContinue

# USE TEST SECRET WRITE TO VERIFY PERMISSIONS HAVE REPLICATED
Write-Host "Verifying Keyvault configuration..."
[bool]$bContinue = $true
[int]$maxCount = 20
[int]$count = 0
while ($bContinue){
    Write-Host "." -NoNewline
    $result = Set-AzKeyVaultSecret -VaultName $gh["KeyVaultName"] -Name TestSecret -SecretValue (ConvertTo-SecureString (Get-StringRandom) -AsPlainText -Force) -Expires (Get-Date).AddYears($DurationYears) -ErrorAction SilentlyContinue
    $null = Remove-AzKeyVaultSecret -VaultName $gh["KeyVaultName"] -Name TestSecret -Force -ErrorAction SilentlyContinue
    $null = Remove-AzKeyVaultSecret -VaultName $gh["KeyVaultName"] -Name TestSecret -Force -InRemovedState -ErrorAction SilentlyContinue

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

###################################################################################
# CREATE SECRETS IN KEY VAULT
###################################################################################
Write-Host "Checking secrets in Key Vault ..."

# GET OUR GITHUB RUNNER SERVICE PRINCIPAL OBJECT
$spo = (az ad sp show --id $gh['RunnerServicePrincipalId'] | ConvertFrom-Json)

# ADD SECRETS
$secrets = @{
    'clientid' = $spo.appid;
    'clientsecret' = $ENV:CLIENT_SECRET;
    'objectid' = $spo.id;
    'authority' = "https://login.microsoftonline.com/" + $gh['TenantId'];
    'JumpboxPassword' = New-Password (Get-StringRandom);
}

foreach ($secretName in $secrets.Keys){
    # EXPORT JUMPBOX PASSWORD IF FLAG SET TO TRUE (USEFUL FOR TROUBLESHOOTING)
    if (($ExportJumpboxPwd -eq $true) -and ($secretName -eq 'JumpboxPassword')){
        $null = $securesecret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $jumpboxPwdFile -Force
    }

    try {
        Write-Host "`tChecking secret for '$secretName'."
        $result = Get-AzKeyVaultSecret -VaultName $gh['KeyVaultName'] -Name $secretName
    } catch {
        #Write-Host $result
    }

    if (($null -eq $result) -or ($result -eq 0)) {
        Write-Host "`t`tCreating secret '$($secretName)' which expires in $($DurationYears) year(s)."
        if ($secrets[$secretName].GetType().Name -ne "SecureString"){
            $value = ConvertTo-SecureString $secrets[$secretName] -AsPlainText -Force
        }else{
            $value = $secrets[$secretName]
        }
        
        try {
            $result = Set-AzKeyVaultSecret -VaultName $gh['KeyVaultName'] -Name $secretName -SecretValue $value -Expires (Get-Date).AddYears($DurationYears)
            Write-Host "`t`tSecret for '$($secretName)' created successfully."
        } catch {
            Write-Output $result
        }
    } else {
        Write-Host "`t`tSecret $($secretName) already exists. No updates will be performed." -ForegroundColor Yellow
    }
}

###################################################################################
# CREATE GITHUB RUNNER
###################################################################################
$bCreateRunner = $true
if ($bCreateRunner) {
    Write-Host "Installing Github Runner"
    $ghResourceGroup = Get-AzResourceGroup -Name $gh["GithubResourceGroup"] -Location $gh["TargetRegion"] -ErrorAction SilentlyContinue
    if ($null -eq $ghResourceGroup){
        $null = New-AzResourceGroup -Name $gh["GithubResourceGroup"] -Location $gh["TargetRegion"]
    }

    $runner = Get-AzVM -Name $gh["RunnerName"] -ResourceGroupName $gh["GithubResourceGroup"] -ErrorAction SilentlyContinue

    if($null -eq $runner){
        Write-Host "`tNo GitHub Runner named '$($gh["RunnerName"])' was found in resource group '$($gh["GithubResourceGroup"])'."

        # Request GitHub Runner Token from GitHub REST API
        $headers = @{
            'Accept' = 'application/vnd.github+json'
            'Authorization' = 'token ' + $ENV:GITHUB_PAT
        }
        # https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-a-registration-token-for-an-organization
        $ghrtoken = Invoke-RestMethod -Uri "https://api.github.com/repos/$($gh["OrganizationName"])/$($gh["RepoName"])/actions/runners/registration-token" -Method Post -Headers $headers
        
        $content = Get-Content -Path ./ConfigureGh.sh -Raw
        $content = $content.Replace("[[ADMIN_USER_NAME]]", $gh["adminUsername"])
        $content = $content.Replace("[[ORG_NAME]]", $gh["OrganizationName"])
        $content = $content.Replace("[[REPO_NAME]]", $gh["RepoName"])
        $content = $content.Replace("[[TOKEN]]", $ghrtoken.token)
        $content = $content.Replace("[[RUNNER_NAME]]", $gh["RunnerName"])
        $content = $content.Replace("[[LABEL]]", $gh['RunnerLabel'])
        $content | Out-File ConfigureGh.temp -Force
        $content = Get-Content -Path ./ConfigureGh.temp -AsByteStream
        $null = Remove-Item -Path ./ConfigureGh.temp -Force
    
        $linuxConfigScript = [convert]::ToBase64String($content)
            
        if (($null -ne $sshKeyFile) -and ($sshKeyFile.Length -gt 0)){
            $adminPublicKey = (Get-Content $sshKeyFile) | ConvertTo-SecureString -AsPlainText -Force
        }
        else{
            # Check for SSH Key File
            If (Test-Path $env:USERPROFILE\.ssh\$($gh["RunnerName"]).pub) {
                Write-Host "`tSSH key found - Using local SSH key pair."
                #Use Bootstrap User's SSH Key from local filesystem
                $adminPublicKey = (Get-Content $env:USERPROFILE\.ssh\$($gh["RunnerName"]).pub) | ConvertTo-SecureString -AsPlainText -Force
            }
            else {
                #Generate a new SSH Key
                Write-Host "`tSSH Key Not Found - Generating new SSH Key Pair!"
                # ssh-keygen -m PEM -t rsa -b 4096 -C "$($gh['adminUsername'])@$($gh['RunnerName'])" -f $env:USERPROFILE\.ssh\$($gh['RunnerName']) -q -N '""'
                ssh-keygen -b 4096 -t rsa -f "$($ENV:USERPROFILE)\.ssh\$($gh['RunnerName'])" -q -N '""'
                $adminPublicKey = (Get-Content $env:USERPROFILE\.ssh\$($gh["RunnerName"]).pub) | ConvertTo-SecureString -AsPlainText -Force
            }
        }
    
        $vNet = Get-AzVirtualNetwork -Name $gh["SpokeVnetName"] -ResourceGroupName $gh["TargetResourceGroupCore"]
        Write-Host "`tDeploying Virtual Machine '$($gh["RunnerName"].ToLower())' in resource group '$($gh["TargetResourceGroupCore"])'."
        $newAzResourceGroupDeploymentParameters = @{
            Name                  = "deployGitHubRunner_$((New-Guid).Guid.Substring(0,5))"
            virtualMachineName    = $gh["RunnerName"].ToLower()
            adminUsername         = $gh["adminUsername"]
            virtualNetworkId      = $vNet.Id
            ResourceGroupName     = $gh["GithubResourceGroup"]
            subnetName            = "snet-privep-001"
            linuxBase64Script     = $linuxConfigScript
            TemplateFile          = '../ARM/GithubRunner/deploy.json'
            TemplateParameterFile = '../Parameters/GithubRunner/parameters.json'
            adminPublicKey        = $adminPublicKey
        }

        $result = New-AzResourceGroupDeployment @newAzResourceGroupDeploymentParameters

        #TODO: NEED TO CREATE A GROUP TO GRANT LOGIN ACCESS
        #Wait 20 seconds for Azure backplane to update
        # Start-Sleep -Seconds 20
        # $ghrunnervmid = (Get-AzVM -Name $($gh["RunnerName"]) -ResourceGroupName $gh["GithubResourceGroup"]).Id
        # $userid = ""
        # New-AzRoleAssignment -ObjectID $userid -RoleDefinitionName "Virtual Machine Administrator Login" -Scope $ghrunnervmid
    
        Write-Host "`tGitHub Runner '$($gh["RunnerName"].ToLower())' created."

    } else {
        Write-Host "`GitHub Runner '$($gh["RunnerName"])' already exists in resource group '$($gh["TargetResourceGroupCore"])'." -ForegroundColor Yellow
    }
} else {
    Write-Host "`tGitHub Runner '$($gh["RunnerName"])' already exists." -ForegroundColor Yellow
}

Write-Host "Disconnecting $($spo.DisplayName)."
$null = Disconnect-AzAccount

###################################################################################
# REMOVE CACHED SERVICE PRINCIPAL DATA
###################################################################################
if (!$ExportJumpboxCredentials){
    $result = Remove-Item -Path $jumpboxPwdFile -Force -ErrorAction SilentlyContinue
}
$result = Clear-AzContext -Force
$spo = $null
$vault = $null
Write-Host "Bootstrap process completed!" -ForegroundColor Green