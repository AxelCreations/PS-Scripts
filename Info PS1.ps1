#Si estos Scripts no funcionan, se debe importar el módulo de Active Directory
# en PowerShell Ejecutando Import-Module ActiveDirectory

#region Cuentas Active Directory +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    #SCRIPTS RELACIONADOS CON CUENTAS DE USUARIOS

#Información de la cuenta user.name
Get-ADUser -Identity user.name -Properties * | Select-Object DisplayName, EmailAddress, mailNickname, SamAccountName | Format-List
#--

#Información de un listado de cuentas de la ruta "C:\carpeta\archivo.txt"
$users = Get-Content "C:\carpeta\archivo.txt"
foreach($user in $users)
{
    Get-ADUser -Identity $user -Properties * | Select-Object SamAccountName, DisplayName
}
#--

#Buscar usuarios que contengan la palabra *apellido* en el Display Name
Get-ADUser -Filter { Name -Like "*apellido*" } | Select-Object Name | Format-List
#--

#Obtener el usuario logueado en el equipo COMPUTER-555
Get-ADUser ((Get-WmiObject –ComputerName COMPUTER-555 –Class Win32_ComputerSystem -Property * |
    Select-Object -ExpandProperty UserName).Split("\")[1]) -Properties * | Select Name, SamAccountName, Description
#--

#Buscar todos los usuarios bloqueados en el dominio
Search-ADAccount -LockedOut -UsersOnly |
    ForEach-Object {Get-ADUser $_ -Properties * } |
    where { $_.Enabled -eq "TRUE" } |
    Select-Object SamAccountName, UserPrincipalName, LastBadPasswordAttempt, AccountExpirationDate |
    Sort-Object AccountExpirationDate, LastBadPasswordAttempt |
    Format-Table -AutoSize
#--

#Buscar información de bloqueo de la cuenta del usuario user.name en todos los Domain Controllers disponibles
$user = "user.name"
foreach($DC in (Get-ADDomainController -Filter *))
{
    Write-Host $DC.HostName.ToString()
    Get-ADUser $user -Server $DC.HostName -Properties * |
        Select-Object LockedOut, BadLogonCount, LastBadPasswordAttempt, PasswordLastSet, AccountExpirationDate, LastLogonDate, comment
}

#Exportar archivo .csv con todos los usuarios que contengan "Criterio Búsqueda" en el campo Description de AD
Get-ADUser -Filter { Description -Like "*Criterio Descripción*" } -Properties * | Select-Object Name, Description, Title | Export-Csv "C:\carpeta\archivo.csv"

#endregion --------------------------------------------------------------------------------

#region Gupos De Seguridad y de Correo ++++++++++++++++++++++++++++++++++++++++++++++++++++

#    SCRIPTS RELACIONADOS CON GRUPOS DE SEGURIDAD

#Buscar los grupos de seguridad que contengan "*todos los*" en el nombre del grupo
Get-ADGroup -Filter {Name -Like "*todos los*"} | select name
#--

#Buscar todos los miembros del grupo "Usuarios Sistema"
Get-ADGroupMember -Identity "Usuarios Sistema" | select name

#endregion --------------------------------------------------------------------------------


#region Registros de Windows en Equipos remotos del Dominio +++++++++++++++++++++++++++++++

#    SCRIPTS PARA CONSULTAR Y MODIFICAR REGISTROS DE EQUIPOS REMOTOS

#Consultar valor del registro "InitialKeyboardIndicators" de la 
#ruta "USERS\.DEFAULT\Control Panel\Keyboard" en el equipo "COMPUTER-555"
$RemoteBaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("USERS", "COMPUTER-555")
$RemoteKey = $RemoteBaseKey.OpenSubKey(".DEFAULT\Control Panel\Keyboard", $true)
$RemoteKey.GetValue("InitialKeyboardIndicators")

#Modificar valor del registro "InitialKeyboardIndicators" de la 
#ruta "USERS\.DEFAULT\Control Panel\Keyboard" en el equipo "COMPUTER-555"
#colocandole el nuevo valor "25"
$RemoteBaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("USERS", "COMPUTER-555")
$RemoteKey = $RemoteBaseKey.OpenSubKey(".DEFAULT\Control Panel\Keyboard", $true)
$RemoteKey.SetValue("InitialKeyboardIndicators", "25", [Microsoft.Win32.RegistryValueKind]::String)

#endregion --------------------------------------------------------------------------------


#region Equipos de Active Directory +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#    SCRIPTS PARA OBTENER INFORMACIONES DE EQUIPOS DE ACTIVE DIRECTORY

#Obtener el tiempo desde el último reinicio del equipo "COMPUTER-555"
$PC = "COMPUTER-555"
$LastBoot = [System.Management.ManagementDateTimeconverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName $PC).LastBootUpTime)
$elapsedTime = ((Get-Date) - $LastBoot)
$elapsedTime | Format-Table

#Obtener la Versión de BIOS del equipo "COMPUTER-555"
Get-WmiObject Win32_BIOS -ComputerName COMPUTER-555

#Obtener el modelo del equipo "COMPUTER-555"
Get-WmiObject Win32_ComputerSystem -ComputerName OMPUTER-555

#Verificar los equipos del listado "C:\carpeta\archivo.txt" que existen en Active Directory
$PCs = Get-Content "C:\carpeta\archivo.txt"
ForEach($PC in $PCs)
{
    $PC = "*" + $PC + "*"
    Get-ADComputer -Filter { Name -Like $PC } | Select-Object Name | Format-List
}

#Obtener la MAC Address del equipo COMPUTER-555
Get-WmiObject -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" -ComputerName COMPUTER-555 | 
    Select-Object -Property *

#endregion --------------------------------------------------------------------------------


#region Reportes en Base a los Equipos del Dominio +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#    SCRIPT PARA OBTENER EL TIEMPO DE ACTIVIDAD DE TODOS LOS EQUIPOS Y EXPORTAR .CSV

$PCs = Get-ADComputer -Filter * -SearchBase "OU=Equipos Dominio,DC=contoso,DC=com,DC=do" | Select-Object Name | Sort-Object Name
$conteo = 0
$Report = ForEach($PC in $PCs)
{
    Clear-Host
    $conteo = $conteo + 1
    $progress = [string]::Format("{0} {1}{2}", "Evaluated...", (($conteo / $PCs.Count) * 100).ToString().Trim(), "%")
    Write-Host $progress

    if ( (Test-Connection -ComputerName $PC.Name -Count 1 -Quiet) -eq $true )
    {
        #Logged User
        if( ([string]::IsNullOrEmpty((Get-WmiObject –ComputerName $PC.Name –Class Win32_ComputerSystem -Property * | Select-Object -ExpandProperty UserName))) )
        {
            $User = [string]::Empty
        }
        else
        {
            $User = Get-ADUser ((Get-WmiObject –ComputerName $PC.Name –Class Win32_ComputerSystem -Property * |
                                    Select-Object -ExpandProperty UserName).Split("\")[1]) -Properties * | Select Name, SamAccountName
        }

        #Get Computer UpTime
        $LastBoot = [System.Management.ManagementDateTimeconverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName $PC.Name).LastBootUpTime)
        $TIME = ((Get-Date) - $LastBoot)

        #Mark Status Online
        $status = "ONLINE"
    }
    else
    {
        #Mark Status Offline
        $status = "OFFLINE"
    }

    #Set N/A to user if not Available
    if ([string]::IsNullOrEmpty($TIME))
    {
        $TIME = New-Object psobject
        $TIME | Add-Member -Name Days -MemberType NoteProperty -Value "N/A"
        $TIME | Add-Member -Name Hours -MemberType NoteProperty -Value "N/A"
        $TIME | Add-Member -Name Minutes -MemberType NoteProperty -Value "N/A"
    }

    #Set N/A to user if not Available
    if ([string]::IsNullOrEmpty($User))
    {
        $User = New-Object psobject
        $User | Add-Member -Name Name -MemberType NoteProperty -Value "N/A"
        $User | Add-Member -Name SamAccountName -MemberType NoteProperty -Value "N/A"
    }

    #Get Computer OU
    $OU = (Get-ADComputer $PC.Name).DistinguishedName

    #Create Report Object
    $Obj = New-Object psobject
    $Obj | Add-Member -Name Computer -MemberType NoteProperty -Value $PC.Name
    $Obj | Add-Member -Name Connection -MemberType NoteProperty -Value $status
    $Obj | Add-Member -Name User -MemberType NoteProperty -Value $User.SamAccountName
    $Obj | Add-Member -Name DisplayName -MemberType NoteProperty -Value $User.Name
    $Obj | Add-Member -Name Days -MemberType NoteProperty -Value $TIME.Days.ToString()
    $Obj | Add-Member -Name Hours -MemberType NoteProperty -Value $TIME.Hours.ToString()
    $Obj | Add-Member -Name Minutes -MemberType NoteProperty -Value $TIME.Minutes.ToString()
    $Obj | Add-Member -Name OU -MemberType NoteProperty -Value $OU
    $Obj

    $TIME = [string]::Empty
    $User = [string]::Empty
    $OU = [string]::Empty
}

$Report | Export-Csv "C:\carpeta\archivo.csv"
Start "Report.csv"
#--------------------------------------------

#    SCRIPT PARA OBTENER VERSION DE WINDOWS DE TODOS LOS EQUIPOS Y EXPORTAR .CSV

$PCs = Get-ADComputer -Filter * -SearchBase "OU=Equipos Dominio,DC=contoso,DC=com,DC=do" | Select-Object Name | Sort-Object Name
$conteo = 0
$Report = ForEach($PC in $PCs)
{
    Clear-Host
    $conteo = $conteo + 1
    $progress = [string]::Format("{0} {1}{2}", "Evaluated...", (($conteo / $PCs.Count) * 100).ToString().Trim(), "%")
    Write-Host $progress

    $IP = (Get-ADComputer $PC.Name -Properties * | Select-Object IPv4Address).IPv4Address
    
    Write-Host "TEST-CONNECTION"
    if ( (Test-Connection -ComputerName $IP -Count 1 -Quiet) -eq $true )
    {

        #Get OS Information
        Write-Host "GET-OS"
        $OS = Get-WMIObject -ComputerName $IP Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

        #Mark Status Online
        $status = "ONLINE"
    }
    else
    {
        #Mark Status Offline
        $status = "OFFLINE"
    }

    #Set N/A to OS if not Available
    if ([string]::IsNullOrEmpty($OS))
    {
        $OS = New-Object psobject
        $OS | Add-Member -Name Caption -MemberType NoteProperty -Value "N/A"
        $OS | Add-Member -Name Version -MemberType NoteProperty -Value "N/A"
        $OS | Add-Member -Name BuildNumber -MemberType NoteProperty -Value "N/A"
    }

    Write-Host "GET-OU"
    #Get Computer OU
    $OU = (Get-ADComputer $PC.Name).DistinguishedName

    Write-Host "CREATE-PSOBJECT"
    #Create Report Object
    $Obj = New-Object psobject
    $Obj | Add-Member -Name Computer -MemberType NoteProperty -Value $PC.Name
    $Obj | Add-Member -Name Connection -MemberType NoteProperty -Value $status
    $Obj | Add-Member -Name IP -MemberType NoteProperty -Value $IP
    $Obj | Add-Member -Name OS -MemberType NoteProperty -Value $OS.Caption
    $Obj | Add-Member -Name OSVersion -MemberType NoteProperty -Value $OS.Version
    $Obj | Add-Member -Name BuildNumber -MemberType NoteProperty -Value $OS.BuildNumber
    $Obj | Add-Member -Name OU -MemberType NoteProperty -Value $OU
    $Obj

    $OS = [string]::Empty
    $OU = [string]::Empty
}

$Report | Export-Csv "C:\carpeta\archivo.csv"
Start "Report.csv"

#endregion --------------------------------------------------------------------------------
