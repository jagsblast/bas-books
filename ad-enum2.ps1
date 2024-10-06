# Obfuscating Domain and Current User
$domain = (Get-WmiObject -Class "Win32_ComputerSystem").Domain
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Random Sleep to simulate legit activity
Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 20)

# Enumerating Domain Controllers
Write-Host "Enumerating Domain Controllers..."
try {
    Get-ADDomainController -Filter * | ForEach-Object {
        Write-Host $_.HostName
    }
} catch {
    Write-Host "Error enumerating Domain Controllers: $_"
}

# Random sleep to slow down execution
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)

# Enumerating Users
Write-Host "Enumerating Users..."
try {
    Get-ADUser -Filter * -Property DisplayName, SamAccountName, Enabled | ForEach-Object {
        # Limit console output to enabled users
        if ($_.Enabled) {
            Write-Host "$($_.DisplayName), $($_.SamAccountName), $($_.Enabled)"
        }
    }
} catch {
    Write-Host "Error enumerating Users: $_"
}

# Sleeping to avoid overuse of system resources
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)

# Enumerating Groups
Write-Host "Enumerating Groups..."
try {
    Get-ADGroup -Filter * | ForEach-Object {
        Write-Host $_.Name
    }
} catch {
    Write-Host "Error enumerating Groups: $_"
}

# Checking Trust Relationships
Write-Host "Checking Trust Relationships..."
try {
    $isPartOfDomain = (Get-WmiObject -Class "Win32_ComputerSystem").PartOfDomain
    Write-Host "Part of Domain: $isPartOfDomain"
} catch {
    Write-Host "Error checking Trust Relationships: $_"
}

# Enumerating Network Shares
Write-Host "Enumerating Network Shares..."
try {
    $shares = Get-WmiObject -Class "Win32_Share" | Select-Object Name, Path
    $shares | ForEach-Object {
        Write-Host "$($_.Name), $($_.Path)"
    }
} catch {
    Write-Host "Error enumerating Shares: $_"
}

# Enumerating Active Sessions
Write-Host "Enumerating Active Sessions..."
try {
    $logonSessions = Get-WmiObject -Class "Win32_LogonSession"
    $logonSessions | ForEach-Object {
        Write-Host "$($_.LogonId), $($_.StartTime)"
    }
} catch {
    Write-Host "Error enumerating Sessions: $_"
}

# Checking Kerberos Delegation
Write-Host "Checking Kerberos Delegation..."
try {
    $delegatedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Property SamAccountName
    $delegatedUsers | ForEach-Object {
        Write-Host $_.SamAccountName
    }
} catch {
    Write-Host "Error checking Kerberos Delegation: $_"
}
