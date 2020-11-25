$SourceForensicPath = "C:\Windows\FData"
$TargetForensicPath = "C:\Windows\FData.7z"
$SZ = ("$env:ProgramFiles\7-Zip\7z.exe") 
$password = "password123"
$ZipArguments = ("a -mx=9 $TargetForensicPath $SourceForensicPath -p$password")
# $ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\autorunsc.exe"
# $ToolArguments = ("-a *", "-nobanner", "-o autoruns.csv", "-c", "-accepteula")
$TargetToolFolder = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
$TargetToolZip = "responsetools.zip"

Write-Output "Starting to unzip $TargetTooLFolder..."
Expand-Archive -Path $TargetToolFolder\$TargetToolZip -DestinationPath "$TargetToolFolder\responsetools" -Force
Write-Output "Sleep 90 seconds to ensure unzip completes..."


Write-Output "Checking that responsetools actually unzipped..."
Try {
    gci $TargetToolFolder -Recurse -ErrorAction Stop
} catch {
    Write-Output "error, couldn't find something..."
    Break
}

# For each tool, we add to the array with its name, arguments, and file path
$ResponseTools = @()
$ResponseTools += [PSCustomObject]@{
    ToolName = "autorunsc.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\autorunsc\autorunsc.exe"
    ToolArguments = ("-a *", "-nobanner", "-o autoruns.csv", "-c", "-accepteula")
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "hollows_hunter64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\hollows_hunter\hollows_hunter64.exe"
    ToolArguments = ("/uniqd")
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "handle64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\handle\handle64.exe"
    ToolArguments = ("")
}


New-Item -Path $SourceForensicPath -ItemType Directory
foreach ($t in $ResponseTools)
{
    # For each tool in the Array, get the path to the executable
    $FullPath = $t.ToolPath + $t.ToolName

    # Make sure it exists before trying to start the process
    if([System.IO.File]::Exists($FullPath)
    {
        Write-Output "[+] Tool $($t.ToolName) found, running..."

        # Generate a unique output file at runtime
        $OutputFileName = $t.ToolName + (Get-Date -Format "yyyyMMdd_HHmm") + ".txt"

        # Start the tool and wait for the process to terminate/exit before zipping
        Start-Process $FullPath -NoNewWindow -ArgumentList $t.ToolArguments -RedirectStandardOutput $OutputFileName -Wait
        
        Write-Output "[+] $($t.ToolName) finished. "
    }
}

Write-Output "[*] Zipping output into single file for download..."
Start-Process $SZ -ArgumentList $ZipArguments
Start-Sleep -s 90

Write-Output "[*] Cleaning up output..."
Remove-Item -Path "C:\Windows\FData" -Recurse
