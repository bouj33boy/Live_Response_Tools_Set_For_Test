<#
.DESCRIPTION
This is basically a port of Matt Graeber's PowerSploit Out-MiniDump project.
One of the main issues with the PowerSploit project is that the Out-MiniDump function flags defender.

.PARAMETERS Process
You can use, process ID or process name to identify the target process and save it in the parameter.

.EXAMPLE PowerShell
./Collect-ProcessMemoryDump.ps1 -Process (Get-Process -Name Calculator) -DumpFilePath 'C:\Windows\FData'
./Collect-ProcessMemoryDump.ps1 -Process (Get-Process -Id 981) -DumpFilePath 'C:\Windows\FData'

.EXAMPLE DATP LIVE RESPONSE
run Collect-ProcessMemoryDump.ps1 -parameters "(Get-Process -Name taskhostw) C:\Windows\FData"

.EXAMPLE PSRemoting

Authors: Josh Prager, Brandon Scullion

.TODO

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Position = 1)]
        [String[]]
        $DumpFilePath
    )

    BEGIN {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $processdumpwritedump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }

    PROCESS {
        try {
                if (!(Test-Path -Path $DumpFilePath -PathType Leaf)) {
                        Write-Verbose "The destination file path $DumpFilePath does not exist. Building."
                        New-Item -ItemType Directory -Path $DumpFilePath -Force | Out-Null
                    } elseif ((Test-Path -Path $DumpFilePath -PathType Leaf) -eq $true ) {
                        Write-Verbose "The destination file path $DumpFilePath exists."
                        continue
                    }
                } catch {
                Write-Error "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                }
                
        $ProcessId = $Process.Id
        $ProcessName = $Process.Name
        $ProcessHandle = $Process.Handle
        $ProcessFileName = "$($ProcessName)_$($ProcessId).dmp"
        $ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName    

        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)

        $Result = $processdumpwritedump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FileStream.Close()

        if (-not $Result)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessName):$($ProcessId))"

            # Remove any partially written dump files. For example, a partial dump will be written
            # in the case when 32-bit PowerShell tries to dump a 64-bit process.
            Remove-Item $ProcessDumpPath -ErrorAction SilentlyContinue

            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $ProcessDumpPath
            Write-Host "*******************************"
            Write-Host "[i] Collection File for Module Collect-ProcessMemoryDump.ps1 should be located on the host at '$ProcessDumpPath'"
            Write-host "*******DATP LIVE RESPONSE NEXT COMMANDS*******"
            Write-Host "[Command]: fileinfo $($ProcessDumpPath)"
            Write-Host "[Command]: getfile $($ProcessDumpPath)"
            Write-host "*******POWERSHELL REMOTING NEXT COMMANDS*******"
            Write-Host "[Command]: copy-item $($ProcessDumpPath) -Destination "~\Downloads" -FromSession `$Session"
            Write-Host "*******************************"
        }
    }
    

    END {}

