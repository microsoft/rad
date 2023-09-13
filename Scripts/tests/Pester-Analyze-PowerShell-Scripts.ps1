Param (
    #[Parameter()]
    #[boolean] $installDependencies = $false,
    [Parameter()]
    [boolean] $CI = $false
)

# Retaining this block if needed in the future
# Install Dependencies if not present
# if($installDependencies){
#     Write-Output "Installing Dependencies . . ."
#     $modules = Get-Module -list

#     if ($modules.Name -notcontains 'pester') {
#         Write-Output "Installing Pester . . ."
#         Install-Module -Name Pester -Force -SkipPublisherCheck
#         Write-Output "Pester Version :$(Get-InstalledModule pester).version"
#     }

#     if ($modules.Name -notcontains 'psscriptanalyzer') {
#         Write-Output "Installing PSScriptAnalyzer . . ."
#         Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck
#         Write-Output "PSScriptAnalyzer Version: $(Get-InstalledModule psscriptanalyzer).version"
#     }

#     else {
#         if($(Get-Module Pester).Version.Major -lt 5){
#             Update-Module -name Pester -Force
#         }
#     }
# }

# Get all Scripts in Parent Folder
$currentDirectory = ($PSScriptRoot)
$parentDirectory = (get-item $currentDirectory).parent.FullName
$scripts = Get-ChildItem $parentDirectory -filter *.ps1 |  ForEach-Object { $_.FullName }
$moduleTestFile = Join-Path -Path $currentDirectory -ChildPath 'psscriptanalyzer.tests.ps1'

# Run pester test against all Scripts
$FailedTests = 0
foreach($file in $scripts) {

    Write-Output "`nPSScriptAnalyzer Testing . . . $(Split-Path -Path $file -Leaf)"
    
    #Retaining this line if needed in the futrure. 
    #$relativeModule = "../$(Split-Path -Path $file -Leaf)"
    
    $container = New-PesterContainer -Path $moduleTestFile -Data @{ File = $file }

    if($CI) {
        $PesterRun = Invoke-Pester -CI -Container $container -PassThru
    }

    else {
        $PesterRun = Invoke-Pester -Container $container -PassThru
        $FailedTests = $FailedTests + $PesterRun.FailedCount
    }    
}

if(!$CI) {
    Write-Output "`nResults"
    Write-Output "====================="
    Write-Output "Failed Test Count: $($FailedTests)"
}