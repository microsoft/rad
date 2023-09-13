<#
	.NOTES
		==============================================================================================
		Copyright(c) Microsoft Corporation. All rights reserved.

		File:		Set-AkvSecrets.ps1

		Purpose:	Set Network Security Group Key Secrets

		Version: 	3.0.0.0 - 1st November 2020
		==============================================================================================

		DISCLAIMER
		==============================================================================================
		This script is not supported under any Microsoft standard support program or service.

		This script is provided AS IS without warranty of any kind.
		Microsoft further disclaims all implied warranties including, without limitation, any
		implied warranties of merchantability or of fitness for a particular purpose.

		The entire risk arising out of the use or performance of the script
		and documentation remains with you. In no event shall Microsoft, its authors,
		or anyone else involved in the creation, production, or delivery of the
		script be liable for any damages whatsoever (including, without limitation,
		damages for loss of business profits, business interruption, loss of business
		information, or other pecuniary loss) arising out of the use of or inability
		to use the sample scripts or documentation, even if Microsoft has been
		advised of the possibility of such damages.

		IMPORTANT
		==============================================================================================
		This script uses or is used to either create or sets passwords and secrets.
		All coded passwords or secrests supplied from input files must be created and provided by the customer.
		Ensure all passwords used by any script are generated and provided by the customer
		==============================================================================================

	.SYNOPSIS
		Set Network Security Group Key Secrets.

	.DESCRIPTION
		Set Network Security Group Key Secrets.

		Deployment steps of the script are outlined below.
		1) Set Azure KeyVault Parameters
		2) Set Network Security Group Parameters
		3) Create Azure KeyVault Secret

	.PARAMETER keyVaultName
		Specify the Azure KeyVault Name parameter.

	.PARAMETER networkSecurityGroupName
		Specify the Network Security Group Name output parameter.

	.PARAMETER networkSecurityGroupResourceId
		Specify the Network Security Group ResourceId output parameter.

	.PARAMETER networkSecurityGroupResourceGroup
		Specify the Network Security Group ResourceGroup output parameter.

	.EXAMPLE
		Default:
		C:\PS>.\Set-AkvSecrets.ps1
			-keyVaultName "$(keyVaultName)"
			-networkSecurityGroupName "$(networkSecurityGroupName)"
			-networkSecurityGroupResourceId "$(networkSecurityGroupResourceId)"
			-networkSecurityGroupResourceGroup "$(networkSecurityGroupResourceGroup)"
#>

#Requires -Module Az.KeyVault

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true)]
	[string]$keyVaultName,

	[Parameter(Mandatory = $false)]
	[string]$networkSecurityGroupName,

	[Parameter(Mandatory = $false)]
	[string]$networkSecurityGroupResourceId,

	[Parameter(Mandatory = $false)]
	[string]$networkSecurityGroupResourceGroup
)

#region - KeyVault Parameters
if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['keyVaultName']))
{
	Write-Output "KeyVault Name: $keyVaultName"
	$kvSecretParameters = @{ }

	#region - Network Security Group Parameters
	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['networkSecurityGroupName']))
	{
		Write-Output "Network Security Group Name: $networkSecurityGroupName"
		$kvSecretParameters.Add("NetworkSecurityGroup-Name-$($networkSecurityGroupName)", $($networkSecurityGroupName))
	}
	else
	{
		Write-Output "Network Security Group Name: []"
	}

	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['networkSecurityGroupResourceId']))
	{
		Write-Output "Network Security Group ResourceId: $networkSecurityGroupResourceId"
		$kvSecretParameters.Add("NetworkSecurityGroup-ResourceId-$($networkSecurityGroupName)", $($networkSecurityGroupResourceId))
	}
	else
	{
		Write-Output "Network Security Group ResourceId: []"
	}

	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['networkSecurityGroupResourceGroup']))
	{
		Write-Output "Network Security Group ResourceGroup: $networkSecurityGroupResourceGroup"
		$kvSecretParameters.Add("NetworkSecurityGroup-ResourceGroup-$($networkSecurityGroupName)", $($networkSecurityGroupResourceGroup))
	}
	else
	{
		Write-Output "Network Security Group ResourceGroup: []"
	}
	#endregion

	#region - Set Azure KeyVault Secret
	$kvSecretParameters.Keys | ForEach-Object {
		$key = $psitem
		$value = $kvSecretParameters.Item($psitem)

		if (-not [string]::IsNullOrWhiteSpace($value))
		{
			Write-Output "KeyVault Secret: $key : $value"
			$value = $kvSecretParameters.Item($psitem)
			$paramSetAzKeyVaultSecret = @{
				VaultName   = $keyVaultName
				Name        = $key
				SecretValue = (ConvertTo-SecureString $value -AsPlainText -Force)
				Verbose     = $true
			}
			Set-AzKeyVaultSecret @paramSetAzKeyVaultSecret
		}
		else
		{
			Write-Output "KeyVault Secret: $key - []"
		}
	}
	#endregion
}
else
{
	Write-Output "KeyVault Name: []"
}
#endregion