# Check the domain and current user
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Current Domain: $domain"
Write-Host "Current User: $currentUser"

# Check if the user has domain admin privileges
$isDomainAdmin = (Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.SamAccountName -eq $currentUser.Split('\')[-1] }) -ne $null
if ($isDomainAdmin) {
    Write-Host "User is a Domain Admin."
} else {
    Write-Host "User is not a Domain Admin."
}

# Enumerate Domain Controllers
Write-Host "Enumerating Domain Controllers..."
Get-ADDomainController -Filter *

# Enumerate members of Domain Admins group
Write-Host "Enumerating Domain Admins..."
Get-ADGroupMember -Identity "Domain Admins"

# Enumerate current user permissions
Write-Host "Enumerating user permissions on Active Directory objects..."
Get-ACL "AD:\$domain" | Format-List

# Enumerate GPOs
Write-Host "Enumerating Group Policy Objects..."
Get-GPO -All

# List all users in the domain
Write-Host "Enumerating all users in the domain..."
Get-ADUser -Filter * -Property DisplayName, SamAccountName, Enabled | Select-Object DisplayName, SamAccountName, Enabled

# List all groups in the domain
Write-Host "Enumerating all groups in the domain..."
Get-ADGroup -Filter * | Select-Object Name

# Check the domain's trust relationships
Write-Host "Checking domain trust relationships..."
Get-ADTrust -Filter *

# Enumerate shares
Write-Host "Enumerating network shares..."
Get-WmiObject -Class Win32_Share | Select-Object Name, Path

# Enumerate active sessions on Domain Controllers
Write-Host "Enumerating active sessions on Domain Controllers..."
foreach ($dc in Get-ADDomainController -Filter *) {
    Write-Host "Active sessions on $($dc.HostName):"
    Get-WmiObject -Class Win32_LogonSession -ComputerName $dc.HostName
}

# Check for Kerberos Delegation
Write-Host "Checking for Kerberos Delegation..."
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Property SamAccountName
