$FilesPath = "D:\FilesPath\";
$Files = Get-ChildItem -Path $FilesPath -Filter *.mp4 | Select-Object Name
$FilesNames = Get-Content("D:\FilesPath\FilesNames.txt");
$number = 1;

foreach($name in $FilesNames)
{
    $oldName = ($FilesPath + "lesson$number" + ".mp4");
    $newName = ($FilesPath + "$number - " + $name.Trim() + ".mp4");

    Rename-Item -Path $oldName -NewName $newName

    $number++;
}