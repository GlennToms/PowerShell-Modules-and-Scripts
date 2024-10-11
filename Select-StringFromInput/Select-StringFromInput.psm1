function Select-StringFromInput {
    <#
.SYNOPSIS
Selects lines of text that contain a specified pattern from pipeline input or from one or more files.

.DESCRIPTION
The Select-StringFromInput function selects lines of text that contain a specified pattern from pipeline input or from one or more files.
It is similar to the Select-String cmdlet, but it allows for processing of input from the pipeline.

.PARAMETER InputObject
Specifies the input object(s) to be processed. If this parameter is not specified, and the -Path parameter is specified,
the function will process the contents of the file(s) specified by the -Path parameter. 
This parameter is pipeline enabled.

.PARAMETER Pattern
Specifies the text pattern to match. This parameter is mandatory.

.PARAMETER Path
Specifies one or more paths to the file(s) to be processed. Wildcards are permitted. This parameter is optional.
If this parameter is not specified, the function will process input from the pipeline.

.PARAMETER Recurse
Indicates that the cmdlet searches the specified directory and its subdirectories. This parameter is optional.

.EXAMPLE
Get-ChildItem *.txt | Select-StringFromInput -Pattern "error"

This example gets all the .txt files in the current directory, and pipes them to Select-StringFromInput to search for the word "error".

.EXAMPLE
"this is a test string" | Select-StringFromInput -Pattern "test"

This example uses the pipeline to send the string "this is a test string" to Select-StringFromInput to search for the word "test".

.EXAMPLE
Select-StringFromInput -Path "C:\logs\*.txt" -Pattern "error" -Recurse

This example searches for the word "error" in all .txt files in the C:\logs directory and its subdirectories.

.INPUTS
System.String

.OUTPUTS
Microsoft.PowerShell.Commands.MatchInfo

.NOTES
Created: 2023/04/11
Email: glenn.toms@agilisys.co.uk
Team: Information Security
#>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('PSItem')]
        [PSObject]$InputObject,
        
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Pattern,

        [Parameter(Position = 1, ParameterSetName = 'Set1')]
        [string]$Path,
        
        [Parameter(ParameterSetName = 'Set1')]
        [switch]$Recurse
    )
    
    begin {
        $newline = [Environment]::NewLine
        $params = @{}
    }
    
    process {
        if ($InputObject) {
            $inputString = ($InputObject | Out-String)
            $lines = $inputString -split $newline
            $lines | Select-String $Pattern
        }
        else {
            if ($Path) {
                $params.Path = $Path
                if ($Recurse.IsPresent) {
                    $params.Recurse = $Recurse
                }
            }
            foreach ($Item in (Get-ChildItem @params)) {
                if ($Item.PSIsContainer -eq $false) {
                    Get-Content -Path $Item.Fullname | Select-String $Pattern
                }
            }
        }
    }
}

Export-ModuleMember -Function Select-StringFromInput -Alias grep
