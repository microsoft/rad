#---------------------------------------------------------------------------------------------------------
#	<copyright file="Get-VariableValue.ps1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------

<#
    .SYNOPSIS
        Searches the specified Variables yaml file for the specified variable.

    .PARAMETER VariablesFile
        Full path to the variables file

    .PARAMETER VariableName
        Name of the variable to find in the variables file
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory=$false)]
    [string] $VariablesFile = "..\\Variables-Ring0.yml",

    [Parameter(Mandatory)]
    [string] $VariableName
)

Function Get-Value($YmlSourceFile, [string]$Name){
    [int]$count = 0
    $varFile = Get-Content $YmlSourceFile

    foreach ($line in $varFile){
        if ($line -cmatch $Name){

            if ($line.Length -eq 0){
                $count++
                continue
            }

            #CHECK IF FOLLOWING LINE IS A VALUE
            if (!$varFile[$count+1].Contains("value:")){
                $count++
                continue
            }

            if (!$line.Contains("- name:")){
                $count++
                continue
            }

            $t = $line.Replace("- name:", "").Trim(" ")

            if ($t.Contains("#")){
                $result = $t.Split("#")
                $t = $result[0].Trim()
            }

            if ($t -eq $Name){
                $o = $varFile[$count+1]
                #REMOVE COMMENTS
                if($o.Contains("#")){
                    $position = $o.IndexOf("#")
                    $o = $o.Substring(0,$position)
                }
                if ($o.Contains("value:")){
                    $position = $o.IndexOf(":")
                    $o = $o.Substring($position+1)
                }
                if ($o.Contains(" ")){
                    $o = $o.Replace(" ","")
                }
                return $o
            }
        }
        $count++
    }

    return $null
}

Function IsFunction([string]$source){

    if ($source.Contains('$[')){
        return $true
    }
    
    return $false
}

Function IsVariable([string]$source){

    if (($source.Contains('$(') -or ($source.Contains("variables[")))){
        return $true
    }
    
    return $false
}

Function ResolveVariable ([string]$VariableName, [string]$VariablesFile){

    [bool]$bIsVariable = IsVariable -source $VariableName
    [bool]$bIsFunction = IsFunction -source $VariableName

    # IF PASSED VARIABLE NAME DOESN'T CONTAIN A VARIABLE OR FUNCTION JUST RETURN VALUE
    if ($bIsFunction -eq $false -and $bIsVariable -eq $false){
        return $VariableName
    }

    $varList = $VariableName.Split("$")

    # ADD OUR $ VALUES BACK TO MAKE IDENTIFYING FUNCTIONS REMAINING IN THE LIST EASIER BELOW
    [int]$i=0
    foreach ($_ in $varList){
        $varList[$i] = $_.Replace("(",'$(')
        $i++
    }    

    $iterationCount = 0
    $bContinue = $true

    while($bContinue){

        [int]$count=0

        foreach ($t in $varList){

            if ($t.Length -eq 0){
                $count++
                continue
            }

            # IS FUNCTION
            if (IsFunction -source $t){
                $t = ResolveFunction -source $t
            }

            # IS VARIABLE
            if (IsVariable -source $t){
    
                # FINDS NEXT VARIABLE NAME IN A GIVEN STRING
                $fName = GetNextVariable -source $t
    
                # GET VALUE OF VARIABLE
                $value = Get-Value -Name $fName -YmlSourceFile $VariablesFile
    
                # IN THIS CASE WE HAVE A NESTED FUNCTION WHICH WE DON'T SUPPORT
                # if (IsFunction -source $value){
                #     return $null
                # }
    
                $t = $t.Replace('$(' + $fName + ')', $value).Trim()
            }

            $varList[$count] = $t
            $count++
        }

        $iterationCount++
        if ($iterationCount -gt 50){
            Write-Host "A potential circular variable reference has been detected. Returning Null" -ForegroundColor Yellow
            return $null
        }

        # CHECK OUR VARIABLES LIST AND SEE IF STILL HAVE VARIABLES OR FUNCTIONS 
        # IF WE HAVE A VARIABLE OR FUNCTION, CONTINUE
        if (!(IsFunction $varList) -and !(IsVariable $varList)){
            $bContinue = $false
        }

    }

    # REASSEMBLE OUR COLLECITON OF STRINGS INTO A STRING
    [string]$result = ""
    foreach ($_ in $varList){
        $result += $_
    }

    return $result
}

Function ResolveFunction([string]$source){

    $varList = $source.Split("$")

    # ADD OUR $ VALUES BACK TO MAKE IDENTIFYING FUNCTIONS REMAINING IN THE LIST EASIER BELOW
    [int]$i=0
    foreach ($_ in $varList){
        if (($_[0] -eq '[') -or ($_[0] -eq '(')){
            $varList[$i] = $_.Insert(0,"$")
        }
        $i++
    }    

    $iterationCount = 0
    $bContinue = $true
    
    while($bContinue){

        [int]$count=0

        foreach ($t in $varList){

            if ($t.Length -eq 0){
                $count++
                continue
            }

            # IS FUNCTION
            if (IsFunction -source $t){
                if ($t.Contains("$[lower")){
                    [int]$iStart = $t.IndexOf("(")
                    [int]$iEnd = $t.LastIndexOf(")") - $iStart +1
                    
                    $result = $t.Substring($iStart, $iEnd)
        
                    # CHECK IF OUR RESULT CONTAINS A VARIABLE AND RESOLVE
                    if (IsVariable($result)){
                        $t = $result.Replace("(variables[","$").Replace("])","").Replace("$'",'$(').Replace("'",")")
                    }
                }
            }

            $varList[$count] = $t
            $count++
        }

        $iterationCount++
        if ($iterationCount -gt 50){
            Write-Host "A potential circular variable reference has been detected. Returning Null" -ForegroundColor Yellow
            return $null
        }

        # CHECK OUR VARIABLES LIST AND SEE IF STILL HAVE FUNCTIONS 
        # IF WE HAVE A FUNCTION, CONTINUE
        if (!(IsFunction $varList)){
            $bContinue = $false
        }

        # REASSEMBLE OUR COLLECITON OF STRINGS INTO A STRING
        [string]$result = ""
        foreach ($_ in $varList){
            $result += $_
        }
    }

    return $result
}

Function GetNextVariable([string]$source){
    if ($source.Contains('$(')){

        [int]$iStart = $source.IndexOf("(") + 1
        [int]$iEnd = $source.IndexOf(")") - $iStart

        $result = $source.Substring($iStart, $iEnd)
    }

    return $result
}


$v = Get-Value -Name $VariableName -YmlSourceFile $VariablesFile
$result = ResolveVariable -VariableName $v -VariablesFile $VariablesFile

return $result