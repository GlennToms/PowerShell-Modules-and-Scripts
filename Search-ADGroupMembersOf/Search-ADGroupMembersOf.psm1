function Search-ADGroupMembersOf {
    <#
    .SYNOPSIS
        Search-ADGroupMembersOf is a PowerShell cmdlet that retrieves members of an Active Directory group recursively across multiple domains.
    .DESCRIPTION
        This cmdlet allows you to search for members of an Active Directory group, including nested group members, within one or more specified domains.
        It iterates through the group membership recursively, collecting members from all nested groups until it has retrieved all members.
        The result is a list of group members along with their domain.
    .PARAMETER Name
        Specifies the name of the Active Directory group you want to search for members. This parameter is mandatory.
        You can also use the 'SamAccountName' alias for this parameter.
    .PARAMETER DomainNames
        Specifies the domains in which to search for the specified group. By default, it searches in all domains within the current forest.
        You can provide an array of domain names to limit the search to specific domains.
        You can also use the 'Server' or 'Domain' aliases for this parameter.
    .PARAMETER Credential
        Allows you to specify a credential object for authenticating to the Active Directory if necessary.
        This is useful when searching in domains where different credentials are required.
    .EXAMPLE
        Search-ADGroupMembersOf -Name "MyGroup" -DomainNames "DomainA", "DomainB" -Credential $Credential
        This example searches for the group named "MyGroup" in domains "DomainA" and "DomainB" using the specified credential.
    .NOTES
        Created: 2023/10/01
        
        Team: Information Security
    #>

    [CmdletBinding()]
    param (
        [parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [Alias('SamAccountName')]
        [String]$Name,
        [parameter(Position = 1)]
        [Alias('Server', 'Domain')]
        [String[]]$DomainNames = (Get-ADForest).Domains,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    process {
        $Table = @()
        foreach ($DomainName in $DomainNames) {
            $Done = @()
            $ToDo = @($Name)
            $Continue = $true

            while ($Continue) {
                $ToDo1 = $ToDo
                $ToDo = @()
                foreach ($GroupName in ($ToDo1 | Select-Object -Unique)) {
                    $params = @{
                        Identity = $GroupName
                        Server   = $DomainName
                    }

                    if ($Credential) {
                        $params.Credential = $Credential
                    }
                    try {
                        $GroupMembers = Get-ADPrincipalGroupMembership @params -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    }
                    catch {
                    }
                    $ToDo += $GroupMembers
                    $Done += $GroupName
                }

                $ToDo = $ToDo | Where-Object { $_.DistinguishedName -notin $Done.DistinguishedName }
                if ($ToDo.Length -eq 0) {
                    $Continue = $false
                }
            }

            if ($Done.Length -gt 1) {
                foreach ($Group in $Done) {
                    if ($null -eq $Group.Name) {
                        continue
                    }
                    $GroupDomain = $null
                    $GroupDomain = ($Group.distinguishedName -split ",DC")[1..(($Group.distinguishedName -split ",DC=").Length - 1)] -Join "." -replace "=", ""
                    if ($Credential) {
                        $Account = Get-ADGroup -Identity $Group.Name -Server $GroupDomain -Properties Description -Credential $Credential
                    }
                    else {
                        $Account = Get-ADGroup -Identity $Group.Name -Server $GroupDomain -Properties Description
                    }

                    $Table += New-Object PSObject -Property @{
                        Name        = $Group.Name
                        Domain      = $GroupDomain
                        Description = $Account.Description
                    }
                }
            }
        }
        $Table | Select-Object Name, Domain, Description | Sort-Object Domain, Name
    }
}

Export-ModuleMember -Function Search-ADGroupMembersOf -Alias SDGM
