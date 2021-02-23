# ForensicCopy

$InFile = "C:\Windows\system32\config\SAM"
$OutFile = "C:\Windows\FData\SAMpsremote"
Invoke-Command -FilePath "C:\Users\nc3pt0r\.git\gitlab.nc3pt0r\get-ircollection\DATP\PowerShell\Invoke-ForensicCopy.ps1" -Session $(Get-PSSession) -ArgumentList $InFile, $OutFile #-ScriptBlock {param($Infile, $OutFile) Invoke-ForensicCopy.ps1 $Infile,$Outfile} -ArgumentList $InFile, $OutFile


Invoke-Command -FilePath "C:\Users\nc3pt0r\.git\gitlab.nc3pt0r\get-ircollection\DATP\PowerShell\Collect-SOData.ps1" -Session $(Get-PSSession) -ArgumentList  "AccessToken", $FilePath
