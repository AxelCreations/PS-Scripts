#Modificar atributos de Active Directory de forma masiva
$Users = Import-Csv "C:\Users\Administrator\Desktop\nuevosUsuarios.csv";

ForEach($user in $Users)
{
    $elUsuario = Get-AdUser -Identity $user.usuario -Properties DisplayName,Description,Office,OfficePhone,PostalCode,mail;

    $elUsuario.DisplayName = $elUsuario.Name;
    $elUsuario.Description = $user.Descripcion;
    $elUsuario.Office = $user.Office;
    $elUsuario.OfficePhone = $user.Phone;
    $elUsuario.PostalCode = $user.Codigo;
    $elUsuario.mail = $elUsuario.UserPrincipalName;

    Set-AdUser -Instance $elUsuario;
}

#Importar lista de usuarios, modificarlos y exportar el reporte
$newUsers = Import-Csv "C:\Users\Administrator\Desktop\usuarios.csv"

Clear-Host
$Reporte =
ForEach($usr in $newUsers)
{
    $primerNombre = $usr.primerNombre;
    $letraApellido = $usr.segundoNombre.Substring(0, 1);
    $dominio = $usr.correo.Split("@")[1];
    $correo = $primerNombre + $letraApellido + "@" + $dominio;

    $usr.correo = $correo;

    $Objeto = New-Object psobject
    $Objeto | Add-Member -Name primerNombre -MemberType NoteProperty -Value $usr.primerNombre
    $Objeto | Add-Member -Name segundoNombre -MemberType NoteProperty -Value $usr.segundoNombre
    $Objeto | Add-Member -Name nombre -MemberType NoteProperty -Value $usr.nombre
    $Objeto | Add-Member -Name correo -MemberType NoteProperty -Value $usr.correo
    $Objeto | Add-Member -Name pass -MemberType NoteProperty -Value $usr.pass

    $Objeto
}

$Reporte | Export-Csv "C:\Users\Administrator\Desktop\usuarios.csv"

#--------------


#Exportar usuarios Bloqueados en Active Directory
Get-AdUser -Filter * -Properties SamAccountName | select-object SamAccountName |
    Export-Csv "C:\Users\Administrator\Desktop\nuevosUsuarios.csv";

#Buscar los usuarios bloqueados en AD
Search-ADAccount -LockedOut -UsersOnly | Select-Object SamAccountName |
    Select-Object -First 2 | ForEach {
                                    Unlock-ADAccount $_.SamAccountName
                                }

