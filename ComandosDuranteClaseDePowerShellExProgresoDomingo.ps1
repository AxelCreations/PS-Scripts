#Buscar las cuentas habilitadas en AD
$AdUsers = Get-ADUser -Filter * | Where-Object Enabled -EQ True

#Buscar cuentas mediante Postal Code
Get-ADUser -Filter 'PostalCode -eq 7700' | Select-Object -First 1

#Crear usuarios de Active Directory de manera masiva
Clear-Host
$newUsers = Import-Csv "C:\Users\Administrator\Desktop\usuarios.csv"

$errores = "";

ForEach($user in $newUsers)
{
    $nombre = $user.nombre;
    $primerNombre = $user.primerNombre;
    $apellido = $user.apellido;
    $cuenta = $user.cuenta;
    $correo = $user.correo;
    $pass = ConvertTo-SecureString $user.pass -AsPlainText -Force

    if (Get-AdUser -Filter {SamAccountName -eq $cuenta})
    {
        Write-Warning ("Pero mamaguevazoo yaaa " + $cuenta + " Existe")
    }
    else
    {
        New-ADUser -Name $nombre -GivenName $primerNombre `
        -Surname $apellido -SamAccountName $cuenta -UserPrincipalName $correo `
        -Path "OU=Piso1,OU=Users,OU=AdministratedObject,DC=lapu,DC=com" `
        -AccountPassword($pass) -Enabled $true
    }
}
