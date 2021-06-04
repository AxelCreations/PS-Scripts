# Get where a user is Logged In
##-----------------------------------

# Specify the user that you are looking fo
$theUser = "axel.creations"

# Query all the computers in your domain
$PCs = Get-ADComputer -Filter * | Select-Object Name | Sort-Object Name

$total = ($PCs.Count)
$conteo = 0

# Evaluate each computer on the list $PCs
ForEach($PC in $PCs)
{
    Clear-Host
    $conteo = $conteo + 1
    
    $progreso = ($conteo / $total * 100).ToString() + "%";

    Write-Host -ForegroundColor DarkGray "$progreso. Evaluando $theUser en el equipo " $PC.Name;
    
    # Test if the computer is connected to network
    if ( (Test-Connection -ComputerName $PC.Name -Count 1 -Quiet) -eq $true )
    {
        # Verify the user logged on this computer
        $logon = gwmi win32_LoggedOnUser -ComputerName $PC.Name
        
        # Compare the user found with the one you are looking for
        if ($logon.Antecedent -match $theUser)
        {
            # Report found and stop the Script
            Write-Host "El usuario $theUser se encuentra logueado en el equipo " $PC.Name;
            break
        }
    }
}
