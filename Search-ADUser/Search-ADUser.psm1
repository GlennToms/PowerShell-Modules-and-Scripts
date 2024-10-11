function Search-ADUser {
    <#
    .SYNOPSIS
        Searches for Active Directory users with the specified name.
    .DESCRIPTION
        This function searches for Active Directory users with the specified name(s) in all domains in the current forest.
    .PARAMETER Names
        Specifies one or more names to search for.
    .PARAMETER DomainNames
        Specifies the domain(s) to search in. By default, it searches in all domains in the current forest.
    .PARAMETER Credential
        Specifies the credentials to use for the search.
    .PARAMETER NoWildSearch
        Disables wildcard search when specified. By default, wildcard search is enabled.
    .PARAMETER FilterName
        Specifies a name filter to further refine the search results.
    .EXAMPLE
        Search-ADUser -Names John,Doe
        Searches for users with names that contain "John" or "Doe".
    .EXAMPLE
        Search-ADUser -Names John -NoWildSearch
        Searches for users with exact name "John".
    .EXAMPLE
        Search-ADUser -Names John,Doe -FilterName Smith
        Searches for users with names that contain "John" or "Doe", and then filters the results to only include users with "Smith" in their names.
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
        [switch]$NoWildSearch,
        [string]$FilterName
    )
    
    begin {
        $SearchString = ''
        foreach ($Name in $Names) {
            $Search = "'*$Name*'"
            if ($NoWildSearch.IsPresent) {
                $Search = "'$Name'"
            }
            $SearchString += "Name -like $Search -or SamAccountName -like $Search -or SurName -like $Search -or GivenName -like $Search -or Description -like $Search -or "
        }
        $SearchString = $SearchString -replace " -or $"
    }
    
    process {
        $params = @{
            Filter     = $SearchString
            Properties = @(
                'Name'
                'SurName'
                'GivenName'
                'SamAccountName'
                'LastLogonDate'
                'whenCreated'
                'Enabled'
                'LockedOut'
                'Description'
                'Department'
                'EmailAddress'
                'UserPrincipalName'
                'PasswordLastSet'
                'AccountExpirationDate'
                'MemberOf'
            )
        }
            
        if ($Credential) {
            $params.Credential = $Credential
        }

        
        $DomainNames | Foreach-Object {
            $params.Server = $_
            $Results = Get-ADUser @params
            if ($FilterName) {
                $Results = $Results | Where-Object Name -Like "*$FilterName*"
            }
            foreach ($Result in $Results) {
                $params2 = @{
                    Properties = $($params.properties | Where-Object { $_ -ne 'MemberOf' }) + "Domain", "Groups"
                }
                Add-Member -InputObject $Result -MemberType NoteProperty -Name "Domain" -Value $_ -Force
                # Add-Member -InputObject $Result -MemberType NoteProperty -Name "IsDomainAdmin" -Value $(if ($($Result.MemberOf -replace "CN=", "" -replace "DC=", "" | ForEach-Object { ($_ -split ",")[0].Trim() }) -in "Domain Admins", "Enterprise Admins") { $true } else { $false }) -Force
                Add-Member -InputObject $Result -MemberType NoteProperty -Name "Groups" -Value $(($Result.MemberOf -replace "CN=", "" -replace "DC=", "" | ForEach-Object { ($_ -split ",")[0] } | Sort-Object) -Join ", ") -Force
                
                $Result | Select-Object $params2.Properties
            }
        }
    }

    end {
    }
}
Export-ModuleMember -Function Search-ADUser -Alias SDU
