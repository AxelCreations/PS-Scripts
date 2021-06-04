#Searchbase is the root Directory where the computers should be.
$PCs = Get-Content -Path C:\ComputerList.txt

$total = ($PCs.Count)
$conteo = 0

$Report = ForEach($PC in $PCs)
{
    Clear-Host
    $conteo = $conteo + 1
    $progress = [string]::Format("{0} {1}{2}", "Evaluated...", (($conteo / $PCs.Count) * 100).ToString().Trim(), "%")
    
    Write-Progress -Activity "Scanning" -Status "Evaluated $conteo" -percentComplete ($conteo / $total * 100)

    # Test if computer is online, this is the same to doing a "ping" to the Computer
    if ( (Test-Connection -ComputerName $PC -Count 1 -Quiet) -eq $true )
    {
        Write-Host "Finding Logged User"
        $loggedUser = Get-WmiObject win32_LoggedOnUser -ComputerName $PC
        
        # Get the logged user information in AD
        $userCode = $loggedUser.Antecedent[0].Split(",")[1].Split("""")[1];
        $User = (Get-ADUser $userCode -Properties * | Select SamAccountName, DisplayName, Description)

        $Connection = "Online";
    }
    else
    {
        $Connection = "Offline";
    }

    Write-Host "GET-IP"
    $IP = (Get-ADComputer $PC -Properties * | Select-Object IPv4Address).IPv4Address
    
    Write-Host "GET-OU"
    $OU = (Get-ADComputer $PC).DistinguishedName

    Write-Host "CREATE-PSOBJECT"
    #Create Report Object
    $Obj = New-Object PSOBJECT
    $Obj | Add-Member -Name Equipo -MemberType NoteProperty -Value $PC
    $Obj | Add-Member -Name IP -MemberType NoteProperty -Value $IP
    $Obj | Add-Member -Name OU -MemberType NoteProperty -Value $OU
    $Obj | Add-Member -Name Conexión -MemberType NoteProperty -Value $Connection
    $Obj | Add-Member -Name Código -MemberType NoteProperty -Value $User.SamAccountName
    $Obj | Add-Member -Name Nombre -MemberType NoteProperty -Value $User.DisplayName
    $Obj | Add-Member -Name Departamento -MemberType NoteProperty -Value $User.Description
    $Obj

    $IP = [string]::Empty
    $OU = [string]::Empty
    $Connection = [string]::Empty
    $User = [string]::Empty
    $loggedUser = [string]::Empty
    $userCode = [string]::Empty

    Clear-Host
    Write-Host $progress
}

# Save the report as CSV file
$Report | Export-Csv "Desktop\Report.csv" -Encoding UTF8 -NoTypeInformation
Start "Desktop\Report.csv"
