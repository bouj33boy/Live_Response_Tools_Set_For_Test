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

Write-Output "Begin creation of the $SourceForensicPath..."
Try {
    New-Item -Path $SourceForensicPath -ItemType Directory -Force -ErrorAction Stop
} catch {
    Write-Output "Something went wrong with $SourceForensicPath directory creation...stopping script."
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
$ResponseTools += [PSCustomObject]@{
    ToolName = "velociraptor-v0.5.2-windows-amd64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\velociraptor\velociraptor-v0.5.2-windows-amd64.exe"
    ToolArguments = ("-v artifacts collect Windows.KapeFiles.Targets --args WebBrowsers")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "handle64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\handle\handle64.exe"
    ToolArguments = ("")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "Get-KerberosTicketGrantingTicket.ps1"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\kerberostickets\Get-KerberosTicketGrantingTicket.ps1"
    ToolArguments = ("")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "Get-SOHostData.ps1"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\sohostdata\Get-SOHostData.ps1"
    ToolArguments = ("")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "BLUESPAWN-client-x64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\bluespawn\BLUESPAWN-client-x64.exe"
    ToolArguments = ("--hunt -a Cursory")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "procdump64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\procdump\procdump64.exe"
    ToolArguments = ("-ma -x C:\Windows\Fdata\ dllhost")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "procdump64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\procdump\procdump64.exe"
    ToolArguments = ("-ma -x C:\Windows\Fdata\ rundll32")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "procdump64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\procdump\procdump64.exe"
    ToolArguments = ("-ma -x C:\Windows\Fdata\ csc")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "procdump64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\procdump\procdump64.exe"
    ToolArguments = ("-ma -x C:\Windows\Fdata\ powershell")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "procdump64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\procdump\procdump64.exe"
    ToolArguments = ("-ma -x C:\Windows\Fdata\ cmd")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "loki.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\loki\loki.exe"
    ToolArguments = ("-l ./test-yara.txt -p C:\")
    
}
$ResponseTools += [PSCustomObject]@{
    ToolName = "winpmemx64.exe"
    ToolPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools\winpmem\winpmemx64.exe"
    ToolArguments = ("C:\Windows\Fdata\physicalmem.raw")
    
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
            $OutputFileName = $t.ToolName + (Get-Date -Format "yyyyMMdd_HHmm") + ".csv"

            # Start the tool and wait for the process to terminate/exit before zipping
            Start-Process $FullPath -NoNewWindow -ArgumentList $t.ToolArguments -RedirectStandardOutput $SourceForensicPath\$OutputFileName -wait
            
            Write-Output "[+] $($t.ToolName) finished. "
        } else {
            Write-Output "[ERROR] Path [$FullPath] not found, stopping script..."
        }
}

Write-Output "[*] Zipping output into single file for download..."
Start-Process $SZ -ArgumentList $ZipArguments -wait
#Start-Sleep -s 90

Write-Output "[*] Cleaning up output...test"
#Remove-Item -Path "C:\Windows\FData" -Recurse
