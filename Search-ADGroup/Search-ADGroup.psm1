function Search-ADGroup {
    <#
    .SYNOPSIS
        Searches all Active Directory domains for groups based on Name, SamAccountName, or Description.
    .DESCRIPTION
        This function searches Active Directory for groups based on the provided names. It can search across all domains in a forest, and supports partial name matching. By default, it returns a table of group objects with the Name, SamAccountName, Description, mail, and distinguishedName properties.
    .PARAMETER Names
        The names of the groups to search for. Can be a single name or an array of names. Wildcards are supported by default.
    .PARAMETER DomainNames
        The names of the domains to search. Can be a single domain or an array of domains. By default, it searches all domains in the forest.
    .PARAMETER Credential
        Specifies a user account to use for the search. This account should have appropriate permissions to search Active Directory.
    .PARAMETER NoWildSearch
        Disables partial name matching. Only exact name matches will be returned.
    .EXAMPLE
        Search-ADGroup -Names VPN
        Searches for all groups with "VPN" in their Name, SamAccountName, or Description properties.
    .EXAMPLE
        "VPN", "HOME" | Search-ADGroup
        Searches for the "VPN" and "HOME" groups.
    .EXAMPLE
        Search-ADGroup -Names VPN, HOME -NoWildSearch
        Searches for groups with exact names "VPN" and "HOME".
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
        [Alias('SamAccountName', 'Name')]
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
            $SearchString += "Name -like $Search -or SamAccountName -like $Search -or Description -like $Search -or "
        }
        $SearchString = $SearchString -replace " -or $"
    }

    process {
        $params = @{
            Filter     = $SearchString
            Properties = @(
                'Name'
                'SamAccountName'
                'Description'
                'mail'
                'distinguishedName'
                'Members'
            )
        }
            
        if ($Credential) {
            $params.Credential = $Credential
        }

        $DomainNames | ForEach-Object {
            $params.Server = $_
            $Result = Get-ADGroup @params | Select-Object $params.properties
            if ($Result) {
                Add-Member -InputObject $Result -MemberType NoteProperty -Name "Domain" -Value $_ -Force
            }
            $Result

        }
    }

    end {
    }
}

Export-ModuleMember -Function Search-ADGroup -Alias SDG
