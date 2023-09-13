#---------------------------------------------------------------------------------------------------------
#	<copyright file="Get-AllAdoVariables.ps1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------

<#
    .SYNOPSIS
        Searches the specified GitHub Actions Variables env file and returns all variables and values as a hashtable.

    .PARAMETER VariablesFile
        Full path to the variables file

    .PARAMETER VariableName
        Name of the variable to find in the variables file
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory=$false)]
    [string] $VariablesFile = "..\\Variables-Ring0.yml"
)

$result = @{}
$varFile = Get-Content $VariablesFile
[int]$count = 0

foreach ($line in $varFile){

    if ($line.Length -eq 0){
        $count++
        continue
    }

    #CHECK IF FOLLOWING LINE IS A NAME
    if ($line.Contains("- name:")){

        $t = $line.Replace("- name:", "").Trim(" ")
        if ($t.Contains("#")) {
            $i = $t.IndexOf("#")
            $t = $t.Substring(0,$i).Trim()
        }
        $v = &$PSScriptRoot\Get-VariableValue.ps1 -VariablesFile $VariablesFile -VariableName $t

        if ($null -ne $t){
            if(!$result.Contains($t)){
                $result.Add($t, $v)
            }
        }

    }else {
        continue
    }

}
return $result