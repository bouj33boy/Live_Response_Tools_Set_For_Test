<#
.SYNOPSIS
This script is to be deployed via the Microsoft DATP Live Response Agent in order to initiate additional collection tools during investigation.

.DESCRIPTION
This script is to be deployed via the Microsoft DATP Live Response Agent in order to initiate additional collection tools during investigation.
Requirements:
- Updated responsetoolsconfig.psd1 file included with the responsetools.zip
- responsetools.zip with the appropriate tools required for collection
- Access to DATP Live Response
- The ability to put the zip to the host target folder
- 7z is installed on the host in the correct installation path
- The FData.7z file is able to be retrieved from the host manually

.EXAMPLE

.LINK
autoruns

hollows hunter

bluespawn

kerberostickets

procdump

sohostdata

velociraptor

ntsysteminfo

.NOTES

Author(s): Brian Rietz, Joshua Prager
Co-Author(s): Brandon Scullion
Date: 11-24-2020

Modified Date:
- 11-25-2020

CHANGES
- Original script was named live_response.ps1 -- script was changed to include documentation and dynamic management of tools from a seperate file
- Added a Switch for PowerShell vs Binary type tools as they execute differently

TODO
- Add parameters to only run a single tool -- pull the config file, but only look for a single tool
#>

#################################
#region SET INITIAL VARIABLES ###
#################################
    # Prompt for securestring password for the FData.7z file
        If (!$ZipPassword) {
            Write-Output "Setting password for Secure FData.7z forensic file..."
            $ZipPassword = Read-Host "Enter 7zip Password" -AsSecureString
        }# else {
         #   Write-Output "Password Set, securing the string for Secure FData.7z forensic file..."
         #   $ZipPassword = ConvertTo-SecureString $args[0] -AsPlainText -Force
        #}
    # Set the Forensic path -- where all the data from the collection will initially store on disk
        $SourceForensicPath = "C:\Windows\FData"
    
    # Set the Target Filename for the final zipped forensic file
        $TargetForensicPath = "C:\Windows\FData.7z"
        $SZ = ("$env:ProgramFiles\7-Zip\7z.exe") # 7zip binary location
        $ZipArguments = ("a -mx=9 $TargetForensicPath $SourceForensicPath -p$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ZipPassword))) -bsp1")
    
    # Set the DATP Downloads Folder Path for the Destination Collection
        $DestinationCollectionPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
    
    # Set the expected ResponseTools zip file name
        $DestinationCollectionToolsZip = "responsetools.zip"
    
    # Set Response Tools Configuration Variables
        $ResponseToolsConfigPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\responsetools"
        $ResponseToolsConfigFile = "responsetoolsconfig.psd1"
####################################
#endregion SET INITIAL VARIABLES ###
####################################

###################################
#region UNZIP RESPONSETOOLS ZIP ###
###################################
Write-Output "Starting to unzip [$DestinationCollectionPath\$DestinationCollectionToolsZip]..."
Try {
    # Attempt to change dir to the responsetools folder, if successful, no unzip required and we will change dir back to root directory
    cd "$DestinationCollectionPath\responsetools" -ErrorAction Stop
    Write-Output "[i] Directory [$DestinationCollectionPath\responsetools] appears to be already available."
    cd "$DestinationCollectionPath"
} Catch {
    If ($(Test-Path -Path "$DestinationCollectionPath\responsetools.zip") -eq $true) {
        Expand-Archive -Path $DestinationCollectionPath\$DestinationCollectionToolsZip -DestinationPath "$DestinationCollectionPath\responsetools" -Force
    } else {
        Write-Output "No zip file found for ResponseTools, you will need to run Put <filename> in DATP first"
    }
}

Write-Output "Checking that responsetools actually unzipped..."
Try {
    Get-ChildItem -path $TargetToolFolder -ErrorAction Stop
} catch {
    Write-Output "[ERROR], couldn't find [$DestinationCollectionPath]...Stopping Script"
    Break
}

# If files unzipped we can load the configuration file
Try {
    If ($(Test-Path $ResponseToolsConfigPath\$ResponseToolsConfigFile) -eq $True) {
        $ResponseToolsConfig = Import-PowerShellDataFile $ResponseToolsConfigPath\$ResponseToolsConfigFile -ErrorAction Stop
    } else { #try it anyway
        $ResponseToolsConfig = Import-PowerShellDataFile $ResponseToolsConfigPath\$ResponseToolsConfigFile -ErrorAction Stop
    }
} catch {
    Write-Output "ConfigFile: [$ResponseToolsConfigPath\$ResponseToolsConfigFile] was not found...stopping script"
    Break
}
Write-Output "ResponseToolsConfig has been loaded...TotalCount [$(($ResponseToolsConfig.ResponseTools).count)]"

# Create the forensics directory
Write-Output "Begin creation of the $SourceForensicPath..."
Try {
    New-Item -Path $SourceForensicPath -ItemType Directory -Force -ErrorAction Stop
} catch {
    Write-Output "Something went wrong with $SourceForensicPath directory creation...stopping script."
    Break
}
######################################
#endregion UNZIP RESPONSETOOLS ZIP ###
######################################

###########################################################################
#region BEGIN TO PARSE CONFIG AND LOOP THROUGH THE TOOLS FOR COLLECTION ###
###########################################################################
# For each tool in responstoolsconfig.psd1, we begin to verify file location and run collection for specific tool
# NOTE: Update psd1 config with new tools, arguments, etc...
# Convert psd1 to objects
$i = 0
$toolnames = @() #($ResponseToolsConfig.ResponseTools.keys.split(" "))
foreach ($tool in $($ResponseToolsConfig.ResponseTools)) {
    # Get the names of the responsetools from the config
    $Toolnames += $tool.keys.split(" ")

    # Get the ToolType foreach tool
    Foreach ($toolname in $Toolnames) {
        write-host "[$i] $toolname" -ForegroundColor Green
        $ToolType = $tool.$toolname.ToolType
        write-host "[$i] $ToolType" -ForegroundColor Green
        
        switch ($ToolType) {
            "Binary" {
                # If ToolType = "Binary" -- then we need to call the binary via Start-Proces and it may require ArgumentList formatted differently than a PowerShell Script
                Write-Host "[$i] $Toolname`: ITS A BINARY!" -ForegroundColor Green
                # For each tool in the Array, get the path to the executable
                $FullPath = $tool.$toolname.ToolPath + $tool.$toolname.Toolname
<#TO DO specify procdump target process#>
                    # Make sure it exists before trying to start the process
                    if([System.IO.File]::Exists("$FullPath") )
                    {
                        Write-Output "[+] Tool $($tool.$toolname.ToolName) found, running..."

                        # Generate a unique output file at runtime
                        $OutputFileName = $tool.$toolname.toolname + "_" + (Get-Date -f "yyyyMMdd_HHmm") + ".txt"

                        # Start the tool and wait for the process to terminate/exit before zipping
                        #Start-Process $FullPath -NoNewWindow -ArgumentList $tool.$toolname.ToolArguments -RedirectStandardOutput $SourceForensicPath\$OutputFileName
                        [string]$toolarguments = $($tool.$toolname.ToolArguments)
                        #cmd /c .\responsetools\autorunsc\autorunsc.exe -a * -c -accepteula -nobanner > C:\Windows\FData\autoruns_test.txt
                        #cmd /c "$FullPath $($toolarguments)" > "$SourceForensicPath\$OutputFileName" #> null 2>&1"
                        cmd /c "`"$FullPath`" $toolarguments" > $SourceForensicPath\$OutputFileName
                        #$ExecuteVariable = "cmd /c powershell -command "$FullPath -NoNewWindow -ArgumentList $tool.$toolname.ToolArguments" 
                        #return $ExecuteVariable | Out-File $SourceForensicPath\$OutputFileName
                        #Start-Sleep 60
                        Write-Output "[+] $($tool.$toolname.toolname) finished..."
                    } else {
                        Write-Output "[ERROR] Path [$FullPath] not found, skipping tool..."
                        Break
                    }                
            }
            
            "PowerShell" {
                # If ToolType = "PowerShell" -- Then we will want to run the ps1 script on the host in such a way that the output is saved to disk for us to pull back at a later time.
                Write-Host  "[$i] $Toolname`: ITS A POSH!" -ForegroundColor Yellow
                $FullPath = $tool.$toolname.ToolPath + $tool.$toolname.Toolname
                # Make sure it exists before trying to start the process
                if([System.IO.File]::Exists("$FullPath") )
                {
                    Write-Output "[+] Tool $($tool.$toolname.ToolName) found, running..."

                    # Generate a unique output file at runtime
                    $OutputFileName = $tool.$toolname.toolname + "_" + (Get-Date -f "yyyyMMdd_HHmm") + ".txt"
<# TODO -- FIGURE OUT HOW TO ADD PS1 Scripts into the dynamic toolarray and collect files on host in C:\Windows\FData#>
                    # Start the tool and wait for the process to terminate/exit before zipping
                    # Start-Process $FullPath -NoNewWindow -ArgumentList $t.ToolArguments -RedirectStandardOutput $SourceForensicPath\$OutputFileName -wait -whatif
                    #Start-Sleep 60
                    Write-Output "[+] $($tool.$toolname.toolname) finished..."
                } else {
                    Write-Output "[ERROR] Path [$FullPath] not found, skipping tool..."
                    Break
                }
            }
        }
    $i++
    }
} 

<# THIS WAS FOR TESTING...NOT SURE IF ILL NEED THE LOGIC AGAIN LATER?
$ResponseToolsConfig 
# Verify available tools for collection
$i = 0
Foreach ($tool in $ResponseToolsConfig) {
    $toolname = $ResponseToolsConfig.Values.autoruns
    Write-Output "[$i] $($tool.Toolname)"
    $++
}
#>
##############################################################################
#endregion BEGIN TO PARSE CONFIG AND LOOP THROUGH THE TOOLS FOR COLLECTION ###
##############################################################################

##############################################################################################
#region VERIFY THAT NO PROCESSESS ARE STILL RUNNING AND BEGIN THE FData ZIP FOR EXTRACTION ###
##############################################################################################
<#TODO -- VERIFY PROCESSES ARE NOT RUNNING FROM SCRIPT BEFORE BEGINNING COLLECTION#>
#Start-Sleep -s 300
# Let's zip it up
Write-Output "[*] Zipping output into single file for download..."
Start-Process $SZ -ArgumentList $ZipArguments -wait
#Start-Sleep -s 90

# Once the zip file is password protected...we want to clean up the forensic folder C:\Windows\FData
Write-Output "[*] Cleaning up output..."
#Remove-Item -Path "C:\Windows\FData" -Recurse -force

<# TODO VERIFY CLEANUP WAS SUCCESSFUL#>
#################################################################################################
#endregion VERIFY THAT NO PROCESSESS ARE STILL RUNNING AND BEGIN THE FData ZIP FOR EXTRACTION ###
#################################################################################################