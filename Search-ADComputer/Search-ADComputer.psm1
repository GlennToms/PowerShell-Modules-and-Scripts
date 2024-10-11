function Search-ADComputer {
    <#
    .SYNOPSIS
        Searches for Active Directory computers by name or description.
    .DESCRIPTION
        The Search-ADComputer function searches for Active Directory computers based on the given names or descriptions.
    .PARAMETER Names
        Specifies an array of strings that represent the names or descriptions of the computers to be searched.
    .PARAMETER DomainNames
        Specifies an array of strings that represent the domain names to search in. If not specified, all domains in the forest will be searched.
    .PARAMETER Credential
        Specifies the credentials to use when connecting to the Active Directory server. Required when searching in domains where the current user does not have permission.
    .PARAMETER NoWildSearch
        Specifies a switch to perform an exact match search. By default, wildcards are used.
    .EXAMPLE
        Search-ADComputer -Names "Server1", "Desktop1" -NoWildSearch
        Searches for computers named "Server1" and "Desktop1" without using wildcards.
    .OUTPUTS
        A list of Active Directory computer objects that match the search criteria.
    .NOTES
        Created: 2023/02/23
        Email: glenn.toms@agilisys.co.uk
        Team: Information Security
    #>
    [CmdletBinding()]
    param (
        [parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [Alias('CN', 'Hostname', 'ComputerName', 'Machine', 'System', 'Name')]
        [String[]]$Names,
        [parameter(Position = 1)]
        [Alias('Server')]
        [String[]]$DomainNames = (Get-ADForest).Domains,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$NoWildSearch
    )
    
    begin {
        $SearchString = ''
        foreach ($Name in $Names) {
            $Search = "'*$Name*'"
            if ($NoWildSearch.IsPresent) {
                $Search = "'$Name'"
            }
            $SearchString += "Name -like $Search -or Description -like $Search -or "
        }
        $SearchString = $SearchString -replace " -or $"
    }

    process {
        $params = @{
            Filter     = $SearchString
            Properties = @(
                'Name'
                'Description'
                'Enabled'
                'LastLogonDate'
                'OperatingSystem'
                'whenCreated'
                'DNSHostName'
                'DistinguishedName'
            )
        }

        if ($Credential) {
            $params.Credential = $Credential
        }

        $DomainNames | ForEach-Object {
            $params.Server = $_ 
            Get-ADComputer @params | Select-Object $params.properties
        }
    }
    
    end {
    }
}


Export-ModuleMember -Function Search-ADComputer -Alias SDC
