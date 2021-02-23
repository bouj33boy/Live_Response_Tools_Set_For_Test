<#
.DESCRIPTION
Port of PowerSploit Out-MiniDump project.
One of the main issues with the PowerSploit project is that the Out-MiniDump function flags defender.
This script offers a switch for ProcessName or ProcessId

.PARAMETERS $Option
You can choose either ProcessName or ProcessId.
-Option "ProcessName"

.Parameter $ProcessNameInput
You can choose the natural language name of the target process. 
-ProcessNameInput 'calculator'

.Prameter $ProcessIdInput
You can choose the Process ID of the target process.
-ProcessIdInput '16028'

.EXAMPLE Local PowerShell
.\Collect-ProcessMemoryDump.ps1 -Option 'ProcessName' -ProcessNameInput 'calculator' -DumpFilePath 'C:\Windows\FData'
.\Collect-ProcessMemoryDump.ps1 -Option 'ProcessId' -ProcessIdInput '16028' -DumpFilePath 'C:\Windows\FData'

.EXAMPLE PSRemoting
PS C:\Users\da> Invoke-Command -FilePath "C:\Users\da\Documents\Collect-ProcessMemoryDump.ps1" -Session $sessions

cmdlet  at command pipeline position 1
Supply values for the following parameters:
Option: ProcessName
ProcessNameInput: ShellExperienceHost
DumpFilePath: C:\Windows\FData


PS C:\Users\da> Invoke-Command -FilePath "C:\Users\da\Documents\Collect-ProcessMemoryDump.ps1" -Session $sessions

cmdlet  at command pipeline position 1
Supply values for the following parameters:
Option: ProcessId
ProcessIdInput: 2456
DumpFilePath: C:\Windows\FData

.EXAMPLE DATP LIVE RESPONSE
run Collect-ProcessMemoryDump.ps1 -parameters "-Option ProcessName -ProcessNameInput ShellExperienceHost -DumpFilePath C:\Windows\FData"
run Collect-ProcessMemoryDump.ps1 -parameters "-Option ProcessId -ProcessIdInput 5828 -DumpFilePath C:\Windows\FData"


Authors: Josh Prager, Brandon Scullion

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateSet("ProcessId","ProcessName")]
        [string]
        $Option,

        [Parameter(Mandatory = $False)]
        [string]
        $ProcessIdInput,

        [Parameter(Mandatory = $False)]
        [string]
        $ProcessNameInput,

        [Parameter(Mandatory = $False)]
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
                Write-Debug -Message "We chose our folder path - '$DumpFilePath'"

                switch($Option) {
                    "ProcessName" {
                    $ProcessComplete = (Get-Process -Name $ProcessNameInput)
                    $ProcessId = $ProcessComplete.Id
                    $ProcessName = $ProcessComplete.Name
                    $ProcessHandle = $ProcessComplete.Handle
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

                            Write-Debug -Message "We chose our Process Switch - '$ProcessComplete'"
                }
                "ProcessId" {
                    $ProcessComplete = (Get-Process -Id $ProcessIdInput)
                    $ProcessId = $ProcessComplete.Id
                    $ProcessName = $ProcessComplete.Name
                    $ProcessHandle = $ProcessComplete.Handle
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
                            }
                            }
                            Write-Debug -Message "We chose the ProcessID instead - '$ProcessId'"
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
        }
    }

    END {}
