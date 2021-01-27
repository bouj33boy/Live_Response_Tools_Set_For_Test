<#
.DESCRIPTION
This is basically a port of Matt Graeber's PowerSploit Out-MiniDump project.
One of the main issues with the PowerSploit project is that the Out-MiniDump function flags defender.

.PARAMETERS $Process
You can use ONLY process name, currently, to identify the target process and save it in the parameter.

.EXAMPLE Local PowerShell
Need to test Locally***./Collect-ProcessMemoryDump.ps1 -Process 'calculator' -DumpFilePath 'C:\Windows\FData'***
./Collect-ProcessMemoryDump.ps1 -ProcessIdInput (Get-Process -Id 981) -DumpFilePath 'C:\Windows\FData'
.EXAMPLE PSRemoting


.EXAMPLE DATP LIVE RESPONSE
run Collect-ProcessMemoryDump.ps1 -parameters "taskhostw C:\Windows\FData"


Authors: Josh Prager, Brandon Scullion

.TODO
Add switch to change between Name or ProcessId
#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $ProcessIdInput,

        [Parameter(Position = 1)]
        [string]
        $Process,


        [Parameter(Position = 2, Mandatory = $True)]
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
        try {
                if (($Process = $null ) -eq $False) {
                    Write-Verbose "The '$Process' switch is being used."
                    $ProcessComplete = (Get-Process -Name $Process)
                    $ProcessIdProc = $ProcessComplete.Id
                    $ProcessNameProc = $ProcessComplete.Name
                    $ProcessHandleProc = $ProcessComplete.Handle
                    $ProcessFileNameProc = "$($ProcessNameProc)_$($ProcessIdProc).dmp"
                    $ProcessDumpPathProc = Join-Path $DumpFilePath $ProcessFileNameProc
                    
                    $FileStreamProc = New-Object IO.FileStream($ProcessDumpPathProc, [IO.FileMode]::Create)
                    
                    $ResultProc = $processdumpwritedump.Invoke($null, @($ProcessHandleProc,
                                                     $ProcessIdProc,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))
                    
                    $FileStream.Close()
               
                } else (($Process = $null) -eq $True) {
                    Write-Verbose "The '$ProcessIdInput' switch is being used."
                    $ProcessIdIdInput = $ProcessIdInput.Id
                    $ProcessNameIdInput = $ProcessIdInput.Name
                    $ProcessHandleIdInput = $ProcessIdInput.Handle
                    $ProcessFileNameIdInput = "$($ProcessNameIdInput)_$($ProcessIdIdInput).dmp"
                    $ProcessDumpPathIdInput = Join-Path $DumpFilePath $ProcessFileNameIdInput

                                        
                    $FileStreamIdInput = New-Object IO.FileStream($ProcessDumpPathIdInput, [IO.FileMode]::Create)
                    
                    $ResultIdInput = $processdumpwritedump.Invoke($null, @($ProcessHandleIdInput,
                                                     $ProcessIdIdInput,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))
                    
                    $FileStream.Close()
                    continue
                    }

                } catch {
                Write-Error "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                }
            

        
<#
        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)

        $Result = $processdumpwritedump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FileStream.Close()
#>
        if (-not $ResultProc)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessNameProc):$($ProcessIdProc))"

            # Remove any partially written dump files. For example, a partial dump will be written
            # in the case when 32-bit PowerShell tries to dump a 64-bit process.
#            Remove-Item -Path $ProcessDumpPathProc -ErrorAction SilentlyContinue

#            throw $ExceptionMessage
        }
        elseif (-not $ResultIdInput)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessNameIdInput):$($ProcessIdIdInput))"

            # Remove any partially written dump files. For example, a partial dump will be written
            # in the case when 32-bit PowerShell tries to dump a 64-bit process.
 #           Remove-Item -Path $ProcessDumpPathIdInput -ErrorAction SilentlyContinue

#            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $ProcessDumpPathProc
            Get-ChildItem $ProcessDumpPathIdInput
            Write-Host "*******************************"
            Write-Host "[i] Collection File for Module [$($args[0])] should be located on the host at '$ProcessDumpPathProc' or '$ProcessDumpPathIdInput'"
            Write-host "*******DATP LIVE RESPONSE NEXT COMMANDS*******"
            Write-Host "[Command]: fileinfo $($ProcessDumpPathProc)"
            Write-Host "[Command]: getfile $($ProcessDumpPathProc)"
            Write-host "*******POWERSHELL REMOTING NEXT COMMANDS*******"
            Write-Host "[Command]: copy-item $($ProcessDumpPathProc) -Destination "~\Downloads" -FromSession `$Session"
            Write-Host "*******************************"

        }

    }

    END {}