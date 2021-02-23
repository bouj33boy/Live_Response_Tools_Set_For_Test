function Decompress-Content
{
<#
.Synopsis
The script is used to decomopress content that was compressed using IO.Compression.DeflateStream

.Description
The script is used to decomopress content that was compressed using IO.Compression.DeflateStream
The compression action is found in Collect-SOData and Invoke-PowerForensics

.Parameter FileName
User must specify filename if in current directory of PowerShell session or specify full file path. This will be confirmed in the script.

.Parameter OutFilePath
User option to specify where they want the saved decompressed file stored. DEFAULT: Users Downloads Directory.

.Example
Decompress-Content -FileName C:\Users\USER\Downloads\compressed.json -OutFilePath C:\users\USER\Downloads\decompressed.json 

This allows user to specify content file and outfilepath and filename

.Example
Decompress-Content -FileName C:\Users\USER\Downloads\compressed.json

This will decompress content and store in default outfile location for users downloads folder

.Link

.Notes
Author(s): Brandon Scullion, Josh Prager
Date: 01-20-2021
Last Updated: 01-22-2021

TODO:
  - DOCUMENT THIS BETTER
#>
param
(
    [Parameter(Mandatory = $true)]
    [string]
    $FileName,
    [Parameter(Mandatory = $false)]
    [string]
    $OutFilePath
)
    # Get Filename parameters from user input
        $FullFileName = Get-ChildItem $FileName | select -ExpandProperty fullname
        $FileBaseName = Get-ChildItem $FileName | select -ExpandProperty name
        $NewFileName = $FileBaseName.trim('compressed.json') + "decompressed.json"    
    # Get Content From identified file. Ensures full path of file is obtained
        $Content = Get-Content $FullFileName
    
    # Set Decompression File Path, Default to User's downloads directory
    If (!$OutFilePath) {
        $OutFilePath = "$env:USERPROFILE\Downloads"
    }

    # Decode the base64data derived from Collect-SOData compressed JSON file
    $base64data = $Content | ConvertFrom-Json | select -ExpandProperty CompressedContent
    $compressedcontent = [Convert]::FromBase64String($base64data)
    
    $DeCompressedStream = New-Object IO.MemoryStream
    $DecompressedStream.Write($compressedcontent, 0, $compressedcontent.Length)
    $DeCompressedStream.Seek(0,0) | Out-Null
    
    $DecompressedStreamReader = New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream($DeCompressedStream, [System.IO.Compression.CompressionMode]::Decompress))

    # Save Decompressed streamreader to array
    $DecompressedContents = @()
    while ($line = $DecompressedStreamReader.ReadLine()) 
    {  
        $DecompressedContents += $line
    }

    #Write array of events decompressed to new JSON file. Have to convertFrom JSON 1 more time, then re-package into JSON for final readable output
    $DecompressedContents | ConvertFrom-Json | ConvertTo-Json | Out-File -FilePath $OutFilePath\$NewFileName -force
}

#$FinalOutFile = Decompress-Content -Content $args[0] -OutFilePath $args[1]
#Write-Host "*****TEST OUTPUT: $FinalOutFile"
#Write-Host "[i] Content: [$($args[0])] will be decompressed and saved here: [$($args[1])]"