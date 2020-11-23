function Get-SOHostData
{
    begin
    {
        try
        {
            Get-System
        }
        catch
        {
            Write-Error "Unable to Impersonate NT AUTHORITY\SYSTEM token"
        }

        $hLsa = LsaRegisterLogonProcess

        #region Logon Session Collection
        # Gather Logon Session Information
        $SessionCount, $LuidPtr = LsaEnumerateLogonSessions

        $sessionDict = @{}

        $CurrentLuidPtr = $LuidPtr
        for($i = 0; $i -lt $SessionCount; $i++)
        {
            $LogonSessionInfo = Get-LogonSessionInformation -LuidPtr $CurrentLuidPtr

            if($LogonSessionInfo.LogonId)
            {
                if($LogonSessionInfo -ne $null)
                {
                    Write-Output (New-Object -TypeName psobject -Property $LogonSessionInfo)
                }

                $sessionDict.Add($LogonSessionInfo.LogonId, $LogonSessionInfo.Id)

                #region Kerberos Ticket Granting Ticket Collection
        
                try
                {
                    $TicketGrantingTicketInfo = Get-KerberosTicketGrantingTicketInformation -LsaHandle $hLsa -LogonId $LogonSessionInfo.LogonId -LogonSessionKey $LogonSessionInfo.Id
                    if($TicketGrantingTicketInfo -ne $null)
                    {
                        Write-Output (New-Object -TypeName psobject -Property $TicketGrantingTicketInfo)
                    }
                }
                catch
                {
                    Write-Warning $_
                }

                #endregion Kerberos Ticket Granting Ticket Collection
            }

            $CurrentLuidPtr = [IntPtr]($CurrentLuidPtr.ToInt64() + $LUID::GetSize())
        }
        #endregion Logon Session Collection

        LsaDeregisterLogonProcess -LsaHandle $hLsa
    }

    process
    {
        $procdictionary = New-Object -TypeName 'System.Collections.Generic.Dictionary[int,string]'
        $Processes = Get-Process
        $Service = Get-WmiObject -Class Win32_Service

        foreach($proc in $Processes)
        {
            $procinfo = Get-ProcessKey -Process $proc
            $procdictionary.Add($proc.Id, $procinfo)
        }

        foreach($proc in (Get-Process))
        {
            # I need to figure out what to do with Processes for which I can not obtain a valid handle
            if($proc.Id -ne 0 -and $proc.Id -ne 4 -and $proc.Id -ne $PID) #-and $proc.Handle -ne $null)
            {
                # Get Process Handle
                try
                {
                    $hProcess = OpenProcess -ProcessId $proc.Id -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION
                }
                catch
                {
                    if($_.Exception.Message -ne "OpenProcess Error: The parameter is incorrect")
                    {
                        Write-Warning "Process Handle: $($proc.Id)"
                        Write-Warning $_.Exception.Message
                    }
                }

                # Create a Process Information object instance
                $processinfo = Get-ProcessInformation -Process $proc -ProcessDictionary $procdictionary

                # Get Process Token Handle
                try
                {
                    $hToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
                    
                    if($hToken)
                    {
                        try
                        {
                            $PrimaryToken = Get-AccessTokenInformation -TokenHandle $hToken -LogonSessionDictionary $sessionDict
                            if($PrimaryToken -ne $null)
                            {
                                Write-Output (New-Object -TypeName psobject -Property $PrimaryToken)
                            }

                            $processinfo.Add('TokenKey', $PrimaryToken.Id)

                            CloseHandle -Handle $hProcess
                            CloseHandle -Handle $hToken
                        }
                        catch
                        {
                            $processinfo.Add('TokenKey', $null)
                            Write-Warning "Process Token Query: $($proc.Id)"
                            Write-Warning $_.Exception.Message
                        }
                    }
                }
                catch
                {
                    Write-Warning "Process Token Handle: $($proc.Id)"
                    Write-Warning $_.Exception.Message
                }

                if($processinfo -ne $null)
                {
                    Write-Output (New-Object -TypeName psobject -Property $processinfo)
                }

                foreach($thread in $proc.Threads)
                {
                    $hThread = $null

                    try
                    {
                        try
                        {
                            $hThread = OpenThread -ThreadId $thread.Id -DesiredAccess THREAD_QUERY_INFORMATION
                            $BaseAddress = NtQueryInformationThread -ThreadHandle $hThread
                            $MemoryRegionInfo = Get-MemoryRegionInformation -Process $proc -ProcessKey $processinfo.Id -Address $BaseAddress
                            if($MemoryRegionInfo -ne $null)
                            {
                                Write-Output (New-Object -TypeName psobject -Property $MemoryRegionInfo)
                            }

                            $ThreadInfo = Get-ThreadInformation -Thread $thread -MemoryRegionKey $MemoryRegionInfo.Id -ProcessKey $processinfo.Id -ThreadStartAddress $BaseAddress
                        }
                        catch
                        {
                            if($_.Exception.Message -eq 'OpenThread Error: Access is denied')
                            {
                                $hThread = OpenThread -ThreadId $thread.Id -DesiredAccess THREAD_QUERY_LIMITED_INFORMATION
                                $ThreadInfo = Get-ThreadInformation -Thread $thread -ProcessKey $processinfo.Id
                            }
                            elseif($_.Exception.Message -eq 'OpenThread Error: The parameter is incorrect')
                            {
                                # It is likely that the thread terminated before we could get to it
                            }
                            else
                            {
                                # This is unexpected
                                Write-Warning $_.Exception.Message
                            }
                        }
                        finally
                        {
                            if($hThread)
                            {
                                try
                                {
                                    # Get Thread Token Information
                                    $hToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess TOKEN_QUERY
                                
                                    $ImpersonationToken = Get-AccessTokenInformation -TokenHandle $hToken -PrimaryTokenKey $PrimaryToken.Id -LogonSessionDictionary $sessionDict
                                    Write-Output (New-Object -TypeName psobject -Property $ImpersonationToken)

                                    $ThreadInfo.Add('TokenKey', $ImpersonationToken.Id)

                                    CloseHandle -Handle $hToken
                                    CloseHandle -Handle $hThread
                                }
                                catch
                                {
                                    if($_.Exception.Message -ne 'OpenThreadToken Error: An attempt was made to reference a token that does not exist')
                                    {
                                        # Unexpected Error
                                        Write-Warning "$($_.Exception.Message) ThreadId: $($thread.Id)"
                                    }
                                    else
                                    {
                                        # This thread is not using Impersonation, so we can associate it with the Process's Primary Token
                                        $ThreadInfo.Add('TokenKey', $PrimaryToken.Id)
                                    }
                                }

                                if($ThreadInfo -ne $null)
                                {
                                    Write-Output (New-Object -TypeName psobject -Property $ThreadInfo)
                                }
                            }
                        }
                    }
                    catch
                    {
                        if($_.Exception.Message -ne 'OpenThread Error: The parameter is incorrect')
                        {
                            # Unexpected Error
                            Write-Warning "$($_.Exception.Message) [Proc] $($proc.Id) [THREAD] $($thread.Id)"
                        }
                        else
                        {
                            # The thread stopped before we could query it
                        }
                    }
                }
            }
        }
    }

    end
    {
        RevertToSelf
    }
}

#region Helper Functions

function Get-System
{
    <#
    .SYNOPSIS

    Impersonate the NT AUTHORITY\SYSTEM account's token.

    .DESCRIPTION

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: 
    Required Dependencies: PSReflect, OpenProcessToken (Function), DuplicateToken (Function), ImpersonateLoggedOnUser (Function), CloseHandle (Function)
    Optional Dependencies: None

    .EXAMPLE

    Get-System
    #>

    # Get a Process object for the winlogon process
    # The System.Diagnostics.Process class has a handle property that we can use
    # We know winlogon will be available and is running as NT AUTHORITY\SYSTEM
    $proc = (Get-Process -Name winlogon)[0]

    # Open winlogon's Token with TOKEN_DUPLICATE Acess
    # This allows us to make a copy of the token with DuplicateToken
    $hToken = OpenProcessToken -ProcessHandle $proc.Handle -DesiredAccess $TOKEN_ACCESS::TOKEN_DUPLICATE
    
    # Make a copy of the NT AUTHORITY\SYSTEM Token
    $hDupToken = DuplicateToken -TokenHandle $hToken
    
    # Apply our Duplicated Token to our Thread
    ImpersonateLoggedOnUser -TokenHandle $hDupToken
    
    # Clean up the handles we created
    CloseHandle -Handle $hToken
    CloseHandle -Handle $hDupToken

    if(-not [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM')
    {
        throw "Unable to Impersonate System Token"
    }
}

function Get-Hash
{
    <#
    .SYNOPSIS

    Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.

    .PARAMETER InputObject

    This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.

    .PARAMETER FilePath

    Specifies the path to a file to hash. Wildcard characters are permitted.

    .PARAMETER Text

    A string to calculate a cryptographic hash for.

    .PARAMETER Encoding

    Specified the character encoding to use for the string passed to the Text parameter. The default encoding type is Unicode. The acceptable values for this parameter are:

    - ASCII
    - BigEndianUnicode
    - Default
    - Unicode
    - UTF32
    - UTF7
    - UTF8

    .PARAMETER Algorithm

    Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:
    
    - SHA1
    - SHA256
    - SHA384
    - SHA512
    - MACTripleDES
    - MD5
    - RIPEMD160
    
    If no value is specified, or if the parameter is omitted, the default value is SHA256.
    For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.

    .NOTES
    
    This function was adapted from https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE

    Get-Hash -Text 'This is a string'

    .EXAMPLE

    Get-Hash -FilePath C:\This\is\a\filepath.exe

    #>

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-Hash -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-Hash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}

#endregion Helper Functions

#region Output Functions

function Get-AccessTokenInformation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,
        
        [Parameter(Mandatory = $true)]
        [hashtable]
        $LogonSessionDictionary,

        [Parameter()]
        [string]
        $PrimaryTokenKey
    )

    $TokenUser = GetTokenInformation -TokenInformationClass TokenUser -TokenHandle $TokenHandle
    $TokenOwner = GetTokenInformation -TokenInformationClass TokenOwner -TokenHandle $TokenHandle
    $TokenIntegrityLevel = GetTokenInformation -TokenInformationClass TokenIntegrityLevel -TokenHandle $TokenHandle
    $TokenType = GetTokenInformation -TokenInformationClass TokenType -TokenHandle $TokenHandle
    $TokenSessionId = GetTokenInformation -TokenInformationClass TokenSessionId -TokenHandle $TokenHandle
    $TokenOrigin = GetTokenInformation -TokenInformationClass TokenOrigin -TokenHandle $TokenHandle
    $TokenPrivileges = (GetTokenInformation -TokenInformationClass TokenPrivileges -TokenHandle $TokenHandle | Where-Object {$_.Attributes -like "*ENABLED*"} | select -ExpandProperty Privilege) -join ";"
    $TokenElevation = GetTokenInformation -TokenInformationClass TokenElevation -TokenHandle $TokenHandle
    $TokenElevationType = GetTokenInformation -TokenInformationClass TokenElevationType -TokenHandle $TokenHandle
    $TokenStatistics = GetTokenInformation -TokenInformationClass TokenStatistics -TokenHandle $TokenHandle
    $TokenKey = Get-AccessTokenKey -AuthenticationId $TokenStatistics.AuthenticationId -ModifiedId $TokenStatistics.ModifiedId -TokenId $TokenStatistics.TokenId

    if(-not $PSBoundParameters.ContainsKey('PrimaryTokenKey'))
    {
        $PrimaryTokenKey = $TokenKey
    }

    if($TokenType -eq 'TokenImpersonation')
    {
        $TokenImpersonationLevel = GetTokenInformation -TokenInformationClass TokenImpersonationLevel -TokenHandle $hToken
    }
    else
    {
        $TokenImpersonationLevel = 'None'
    }

    $obj = @{
        SourceType = 'WinEvent-AccessToken'
        Id = $TokenKey.ToString()
        LogonSessionKey = $LogonSessionDictionary[$TokenStatistics.AuthenticationId]
        PrimaryTokenKey = $PrimaryTokenKey
        TokenId = [UInt32]$TokenStatistics.TokenId
        AuthenticationId = [UInt32]$TokenStatistics.AuthenticationId
        ModifiedId = [UInt32]$TokenStatistics.ModifiedId
        UserSid = $TokenUser.Sid.ToString()
        UserName = $TokenUser.Name.Value
        OwnerSid = $TokenOwner.Sid.ToString()
        OwnerName = $TokenOwner.Name.Value
        IntegrityLevel = $TokenIntegrityLevel.ToString()
        Type = $TokenType.ToString()
        ImpersonationLevel = $TokenImpersonationLevel.ToString()
        SessionId = [UInt32]$TokenSessionId
        Origin = [UInt32]$TokenOrigin
        Privileges = $TokenPrivileges
        IsElevated = $TokenElevation.ToString()
        ElevationType = $TokenElevationType.ToString()
    }

    Write-Output $obj
}

function Get-KerberosTicketGrantingTicketInformation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId,

        [Parameter(Mandatory = $true)]
        [string]
        $LogonSessionKey
    )

    $ticket = LsaCallAuthenticationPackage -LsaHandle $LsaHandle -AuthenticationPackageName MICROSOFT_KERBEROS_NAME_A -LogonId $LogonId

    if($ticket.ServiceName -ne $null)
    {
        $obj = @{
            SourceType = 'WinEvent-KerberosTicketGrantingTicket'
            Id = (Get-KerberosTicketGrantingTicketKey -LogonSessionKey $LogonSessionKey -ClientName $ticket.ClientName -DomainName $ticket.DomainName -StartTime $ticket.StartTime).ToString()
            LogonSessionKey = $LogonSessionKey
            ServiceName = $ticket.ServiceName
            TargetName = $TargetName
            ClientName = $ticket.ClientName
            DomainName = $ticket.DomainName
            TargetDomainName = $ticket.TargetDomainName
            AltTargetDomainName = $ticket.AltTargetDomainName
            SessionKeyType = $ticket.SessionKeyType
            SessionKey = ([System.BitConverter]::ToString($ticket.SessionKey).Replace('-',''))
            TicketFlags = $ticket.TicketFlags
            KeyExpirationTime = $ticket.KeyExpirationTime
            StartTime = $ticket.StartTime
            EndTime = $ticket.EndTime
            RenewUntil = $ticket.RenewUntil
            TimeSkew = $ticket.TimeSkew
            #EncodedTicketSize = $ticket.EncodedTicketSize
            #EncodedTicket = $ticket.EncodedTicket
        }
        Write-Output $obj
    }
}

function Get-LogonSessionInformation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LuidPtr
    )

    $Data = LsaGetLogonSessionData -LuidPtr $LuidPtr

    if($Data.LogonId)
    {
        try
        {
            $LogoffTime = ([System.DateTime]::FromFileTimeUtc($Data.LogoffTime))
        }
        catch
        {
            $LogoffTime = ([System.DateTime]::FromFileTime(116444736000000000))
        }
        try
        {
            $KickOffTime = ([System.DateTime]::FromFileTimeUtc($Data.KickOffTime))
        }
        catch
        {
            $KickOffTime = ([System.DateTime]::FromFileTime(116444736000000000))
        }
        try
        {
            $PasswordLastSet = ([System.DateTime]::FromFileTimeUtc($Data.PasswordLastSet))
        }
        catch
        {
            $PasswordLastSet = ([System.DateTime]::FromFileTime(116444736000000000))
        }
        try
        {
            $PasswordCanChange = ([System.DateTime]::FromFileTimeUtc($Data.PasswordCanChange))
        }
        catch
        {
            $PasswordCanChange = ([System.DateTime]::FromFileTime(116444736000000000)) 
        }
        try
        {
            $PasswordMustChange = ([System.DateTime]::FromFileTimeUtc($Data.PasswordMustChange))
        }
        catch
        {
            $PasswordMustChange = ([System.DateTime]::FromFileTime(116444736000000000))
        }

        $obj = @{
            SourceType = 'WinEvent-LogonSession'
            Id = (Get-LogonSessionKey -LogonId $Data.LogonId -Sid $Data.Sid -LogonType $Data.LogonType -AuthenticationPackage $Data.AuthenticationPackage -LogonTime $Data.LogonTime).ToString()
            LogonId = $Data.LogonId
            UserName = $Data.UserName
            LogonDomain = $Data.LogonDomain
            AuthenticationPackage = $Data.AuthenticationPackage
            LogonType = $Data.LogonType.ToString()
            Session = $Data.Session
            Sid = $Data.Sid.ToString()
            LogonTime = ([System.DateTime]::FromFileTimeUtc($Data.LogonTime))
            LogonServer = $Data.LogonServer
            DnsDomainName = $Data.DnsDomainName
            Upn = $Data.Upn
            UserFlags = $Data.UserFlags
            LastSuccessfulLogon = $Data.LastSuccessfulLogon
            LastFailedLogon = $Data.LastFailedLogon
            FailedAttemptCountSinceLastSuccessfulLogon = $Data.FailedAttemptCountSinceLastSuccessfulLogon
            LogonScript = $Data.LogonScript
            ProfilePath = $Data.ProfilePath
            HomeDirectory = $Data.HomeDirectory
            HomeDirectoryDrive = $Data.HomeDirectoryDrive
            LogoffTime = $LogoffTime
            KickoffTime = $KickOffTime
            PasswordLastSet = $PasswordLastSet
            PasswordCanChange = $PasswordCanChange
            PasswordMustChange = $PasswordMustChange
        }
        Write-Output $obj
    }
}

function Get-MemoryRegionInformation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Mandatory = $true)]
        [string]
        $ProcessKey,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Address
    )
    
    $mbi = VirtualQueryEx -ProcessHandle $Process.Handle -BaseAddress $Address

    $obj = @{
        SourceType = 'WinEvent-MemoryRegion'
        Id = (Get-MemoryRegionKey -ProcessKey $ProcessKey -BaseAddress $Address -RegionSize $mbi.RegionSize).ToString()
        ProcessKey = $ProcessKey
        BaseAddress = $mbi.BaseAddress
        #EndAddress -Value ([IntPtr]($mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64()))
        RegionSize =  $mbi.RegionSize
        AllocationBase = $mbi.AllocationBase
        AllocationProtect = $mbi.AllocationProtect.ToString()
        Protect = $mbi.Protect.ToString()
        State = $mbi.State.ToString()
        Type = $mbi.Type.ToString()
    }
    Write-Output $obj
}

function Get-ProcessInformation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.Dictionary[int,string]]
        $ProcessDictionary
    )

    $wmiproc = Get-WmiObject Win32_Process -Filter "ProcessId = '$($Process.Id)'"
    #$KernelPath = QueryFullProcessImageName -ProcessHandle $Process.Handle
    #$PathMismatch = $proc.Path.ToLower() -ne $KernelPath.ToLower()
    try
    {
        $SHA256Hash = (Get-Hash -FilePath $Process.Path -Algorithm SHA256).Hash
    }
    catch
    {
        $SHA256Hash = $null
    }

    try
    {
        $Path = $Process.Path.ToString()
    }
    catch
    {
        $Path = $null
    }

    try
    {
        $ParentProcessKey = $ProcessDictionary[$wmiproc.ParentProcesSid]
    }
    catch
    {
        $ParentProcessKey = $null
    }

    $obj = @{
        SourceType = 'WinEvent-Process'
        Id = (Get-ProcessKey -Process $Process).ToString()
        ParentProcessKey = $ParentProcessKey
        SHA256Hash = $SHA256Hash
        ProcessName = $Process.Name
        ProcessId = $Process.Id
        StartTime = $Process.StartTime
        Path = $Path
        #KernelPath = $KernelPath
        #PathMismatch = $PathMismatch
        CommandLine = $wmiproc.CommandLine
    }
    Write-Output $obj
}

function Get-ThreadInformation
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.ProcessThread]
        $Thread,

        [Parameter()]
        [string]
        $MemoryRegionKey = '0000000000000000000000000000000000000000000000000000000000000000',

        [Parameter(Mandatory = $true)]
        [string]
        $ProcessKey,

        [Parameter()]
        [IntPtr]
        $ThreadStartAddress = 0
    )

    $obj = @{
        SourceType = 'WinEvent-Thread'
        Id = (Get-ThreadKey -Thread $Thread).ToString()
        MemoryRegionKey = $MemoryRegionKey
        ProcessKey = $ProcessKey
        ThreadId = $Thread.Id
        StartTime = $Thread.StartTime
        ThreadStartAddress = $ThreadStartAddress
        BasePriority = $Thread.BasePriority
        CurrentPriority = $Thread.CurrentPriority
        PriorityBoostEnabled = $Thread.PriorityBoostEnabled
        PriorityLevel = $Thread.PriorityLevel
        #TotalProcessorTime = $Thread.TotalProcessorTime
        #PrivilegedProcessorTime = $Thread.PrivilegedProcessorTime
        #UserProcessorTime = $Thread.UserProcessorTime
        ThreadState = $Thread.ThreadState
        WaitReason = $Thread.WaitReason
    }
    Write-Output $obj
}

#endregion Output Functions

#region Key Generation Functions

function Get-AccessTokenKey
{
    <#
    .SYNOPSIS

    Calculates a unique key (SHA256 Hash) that represents a specific access token instance. This key can be used to correlate disparate sets of data to the same access token.
    
    .DESCRIPTION

    Get-AccessTokenKey calculates a SHA256 Hash for a process based on the token's unique but static data fields.

    The Access Token Key is derived from the following fields:
    - Token Authentication Identifier
    - Token Modified Identifier
    - Token Id
    - Computer Name

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson), Lee Christensen (@tifkin_), and Roberto Rodriguez (@cyb3rward0g)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE
    $hProcess = OpenProcess -ProcessId $proc.Id -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION
    $hToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY, TOKEN_QUERY_SOURCE
    Get-TokenKey -TokenHandle $hToken

    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $AuthenticationId,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $ModifiedId,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $TokenId
    )

    $ComputerName = $env:COMPUTERNAME
    $hashstring = "$($AuthenticationId)|$($ModifiedId)|$($TokenId)|$($ComputerName)"
    Write-Output (Get-Hash -Text $hashstring -Algorithm SHA256).Hash
}

function Get-KerberosTicketGrantingTicketKey
{
    <#
    .SYNOPSIS

    Calculates a unique key (SHA256 Hash) that represents a specific kerberos ticket granting ticket. This hash can be used to correlate disparate sets of data to the same ticket granting ticket.
    
    .DESCRIPTION

    Get-KerberosTicketGrantingTicketKey calculates a SHA256 Hash for a process based on the ticket's unique but static data fields.

    The Kerberos Ticket Granting Ticket Key is derived from the following fields:
    - Logon Session Key
    - Ticket Client Name
    - Ticket Domain Name
    - Ticket Start Time
    - Computer Name

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson), Lee Christensen (@tifkin_), and Roberto Rodriguez (@cyb3rward0g)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $LogonSessionKey,

        [Parameter(Mandatory = $true)]
        [string]
        $ClientName,

        [Parameter(Mandatory = $true)]
        [string]
        $DomainName,

        [Parameter(Mandatory = $true)]
        [string]
        $StartTime
    )

    $ComputerName = $env:COMPUTERNAME
    $hashstring = "$($LogonSessionKey)|$($ClientName)|$($DomainName)|$($StartTime)|$($ComputerName)"
    Write-Output (Get-Hash -Text $hashstring -Algorithm SHA256).Hash
}

function Get-LogonSessionKey
{
    <#
    .SYNOPSIS

    Calculates a unique key (SHA256 Hash) that represents a specific Logon Session. This hash can be used to correlate disparate sets of data to the same Logon Session.
    
    .DESCRIPTION

    Get-LogonSessionKey calculates a SHA256 Hash for a process based on the session's unique but static data fields.

    The Process Key is derived from the following fields:
    - Logon Id
    - Security Id (Sid)
    - Logon Type
    - Authentication Package
    - Logon Time
    - Computer Name

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson), Lee Christensen (@tifkin_), and Roberto Rodriguez (@cyb3rward0g)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId,

        [Parameter(Mandatory = $true)]
        [string]
        $Sid,

        [Parameter(Mandatory = $true)]
        [string]
        $LogonType,

        [Parameter(Mandatory = $true)]
        [string]
        $AuthenticationPackage,

        [Parameter(Mandatory = $true)]
        [string]
        $LogonTime
    )

    $ComputerName = $env:COMPUTERNAME
    $hashstring = "$($LogonId)|$($Sid)|$($LogonType)|$($AuthenticationPackage)|$($LogonTime)|$($ComputerName)"
    Write-Output (Get-Hash -Text $hashstring -Algorithm SHA256).Hash
}

function Get-MemoryRegionKey
{
    <#
    .SYNOPSIS

    Calculates a unique key (SHA256 Hash) that represents a specific memory region. This hash can be used to correlate disparate sets of data to the same memory region.
    
    .DESCRIPTION

    Get-MemoryRegionKey calculates a SHA256 Hash for a process based on the memory region's unique but static data fields.

    The Region Key is derived from the following fields:
    - Process Key
    - BaseAddress
    - RegionSize
    - Computer Name

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson), Lee Christensen (@tifkin_), and Roberto Rodriguez (@cyb3rward0g)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ProcessKey,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress,

        [Parameter(Mandatory = $true)]
        [UIntPtr]
        $RegionSize
    )

    $ComputerName = $env:COMPUTERNAME

    $hashstring = "$($ProcessKey)|$($BaseAddress)|$($RegionSize)|$($ComputerName)"
    Write-Output (Get-Hash -Text $hashstring -Algorithm SHA256).Hash
}

function Get-ProcessKey
{
    <#
    .SYNOPSIS

    Calculates a unique key (SHA256 Hash) that represents a specific process. This hash can be used to correlate disparate sets of data to the same process.
    
    .DESCRIPTION

    Get-ProcessKey calculates a SHA256 Hash for a process based on the process' unique but static data fields.

    The Process Key is derived from the following fields:
    - Process Name
    - Process Id
    - Process Start Time
    - Process Path
    - Computer Name

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson), Lee Christensen (@tifkin_), and Roberto Rodriguez (@cyb3rward0g)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE
    Get-Process | Get-ProcessHash
    #>

    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Diagnostics.Process[]]
        $Process
    )
    
    begin
    {
        #$MachineGuid = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography -Name MachineGuid).MachineGuid
        $ComputerName = $env:COMPUTERNAME
    }
    
    process
    {
        foreach($proc in $Process)
        {
            $hashstring = "$($proc.Name)|$($proc.Id)|$($proc.StartTime.Ticks)|$($proc.Path)|$($ComputerName)"#|$($MachineGuid)"
            Write-Output (Get-Hash -Text $hashstring -Algorithm SHA256).Hash
        }
    }
}

function Get-ThreadKey
{
    <#
    .SYNOPSIS

    Calculates a unique key (SHA256 Hash) that represents a specific thread. This hash can be used to correlate disparate sets of data to the same thread.
    
    .DESCRIPTION

    Get-ThreadKey calculates a SHA256 Hash for a thread based on the thread's unique but static data fields.

    The Thread Key is derived from the following fields:
    - Thread Id
    - Thread Start Time
    - Computer Name

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson), Lee Christensen (@tifkin_), and Roberto Rodriguez (@cyb3rward0g)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .EXAMPLE
    Get-Process | Get-ProcessHash
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.ProcessThread]
        $Thread
    )

    #$MachineGuid = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography -Name MachineGuid).MachineGuid
    $ComputerName = $env:COMPUTERNAME

    $hashstring = "$($Thread.Id)|$($Thread.StartTime.Ticks)|$($ComputerName)"#|$($MachineGuid)"
    Write-Output (Get-Hash -Text $hashstring -Algorithm SHA256).Hash
}

#endregion Key Generation Functions

#region PSReflect

#Requires -Version 2

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.PARAMETER CharSet

Dictates which character set marshaled strings should use.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        }
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion PSReflect

#region PSReflect Definitions

$Module = New-InMemoryModule -ModuleName GetToken

#region Enums

$KERB_CACHE_OPTIONS = psenum $Module KERB_CACHE_OPTIONS UInt64 @{
    KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1
    KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2
    KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4
    KERB_RETRIEVE_TICKET_AS_KERB_CRED   = 0x8
    KERB_RETRIEVE_TICKET_WITH_SEC_CRED  = 0x10 
    KERB_RETRIEVE_TICKET_CACHE_TICKET   = 0x20
    KERB_RETRIEVE_TICKET_MAX_LIFETIME   = 0x40
} -Bitfield

$KERB_PROTOCOL_MESSAGE_TYPE = psenum $Module KERB_PROTOCOL_MESSAGE_TYPE UInt32 @{ 
    KerbDebugRequestMessage                  = 0
    KerbQueryTicketCacheMessage              = 1
    KerbChangeMachinePasswordMessage         = 2
    KerbVerifyPacMessage                     = 3
    KerbRetrieveTicketMessage                = 4
    KerbUpdateAddressesMessage               = 5
    KerbPurgeTicketCacheMessage              = 6
    KerbChangePasswordMessage                = 7
    KerbRetrieveEncodedTicketMessage         = 8
    KerbDecryptDataMessage                   = 9
    KerbAddBindingCacheEntryMessage          = 10
    KerbSetPasswordMessage                   = 11
    KerbSetPasswordExMessage                 = 12
    KerbVerifyCredentialsMessage             = 13
    KerbQueryTicketCacheExMessage            = 14
    KerbPurgeTicketCacheExMessage            = 15
    KerbRefreshSmartcardCredentialsMessage   = 16
    KerbAddExtraCredentialsMessage           = 17
    KerbQuerySupplementalCredentialsMessage  = 18
    KerbTransferCredentialsMessage           = 19
    KerbQueryTicketCacheEx2Message           = 20
    KerbSubmitTicketMessage                  = 21
    KerbAddExtraCredentialsExMessage         = 22
    KerbQueryKdcProxyCacheMessage            = 23
    KerbPurgeKdcProxyCacheMessage            = 24
    KerbQueryTicketCacheEx3Message           = 25
    KerbCleanupMachinePkinitCredsMessage     = 26
    KerbAddBindingCacheEntryExMessage        = 27
    KerbQueryBindingCacheMessage             = 28
    KerbPurgeBindingCacheMessage             = 29
    KerbQueryDomainExtendedPoliciesMessage   = 30
    KerbQueryS4U2ProxyCacheMessage           = 31
}

$KERB_ENCRYPTION_TYPE = psenum $Module KERB_ENCRYPTION_TYPE UInt32 @{
    reserved0                         = 0
    des_cbc_crc                       = 1
    des_cbc_md4                       = 2
    des_cbc_md5                       = 3
    reserved1                         = 4
    des3_cbc_md5                      = 5
    reserved2                         = 6
    des3_cbc_sha1                     = 7
    dsaWithSHA1_CmsOID                = 9
    md5WithRSAEncryption_CmsOID       = 10
    sha1WithRSAEncryption_CmsOID      = 11
    rc2CBC_EnvOID                     = 12
    rsaEncryption_EnvOID              = 13
    rsaES_OAEP_ENV_OID                = 14
    des_ede3_cbc_Env_OID              = 15
    des3_cbc_sha1_kd                  = 16
    aes128_cts_hmac_sha1_96           = 17
    aes256_cts_hmac_sha1_96           = 18
    aes128_cts_hmac_sha256_128        = 19
    aes256_cts_hmac_sha384_192        = 20
    rc4_hmac                          = 23
    rc4_hmac_exp                      = 24
    camellia128_cts_cmac              = 25
    camellia256_cts_cmac              = 26
    subkey_keymaterial                = 65
}

$KERB_TICKET_FLAGS = psenum $Module KERB_TICKET_FLAGS UInt32 @{
    reserved          = 2147483648
    forwardable       = 0x40000000
    forwarded         = 0x20000000
    proxiable         = 0x10000000
    proxy             = 0x08000000
    may_postdate      = 0x04000000
    postdated         = 0x02000000
    invalid           = 0x01000000
    renewable         = 0x00800000
    initial           = 0x00400000
    pre_authent       = 0x00200000
    hw_authent        = 0x00100000
    ok_as_delegate    = 0x00040000
    name_canonicalize = 0x00010000
    cname_in_pa_data  = 0x00040000
    enc_pa_rep        = 0x00010000
    reserved1         = 0x00000001
} -Bitfield

$LuidAttributes = psenum $Module LuidAttributes UInt32 @{
    DISABLED                        = 0x00000000
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED            = 0x00000002
    SE_PRIVILEGE_REMOVED            = 0x00000004
    SE_PRIVILEGE_USED_FOR_ACCESS    = 2147483648
} -Bitfield

$MEMORY_PROTECTION = psenum $Module MEMORY_PROTECTION UInt32 @{
    PAGE_NOACCESS          = 0x00000001
    PAGE_READONLY          = 0x00000002
    PAGE_READWRITE         = 0x00000004
    PAGE_WRITECOPY         = 0x00000008
    PAGE_EXECUTE           = 0x00000010
    PAGE_EXECUTE_READ      = 0x00000020
    PAGE_EXECUTE_READWRITE = 0x00000040
    PAGE_EXECUTE_WRITECOPY = 0x00000080
    PAGE_GUARD             = 0x00000100
    PAGE_NOCACHE           = 0x00000200
    PAGE_WRITECOMBINE      = 0x00000400
    PAGE_TARGETS_NO_UPDATE = 0x40000000
} -Bitfield

$MEMORY_STATE = psenum $Module MEMORY_STATE UInt32 @{
    MEM_COMMIT  = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE    = 0x10000
} -Bitfield

$MEMORY_TYPE = psenum $Module MEMORY_TYPE UInt32 @{
    MEM_PRIVATE = 0x20000
    MEM_MAPPED  = 0x40000
    MEM_IMAGE   = 0x1000000
} -Bitfield

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$SE_GROUP = psenum $Module SE_GROUP UInt32 @{
    DISABLED           = 0x00000000
    MANDATORY          = 0x00000001
    ENABLED_BY_DEFAULT = 0x00000002
    ENABLED            = 0x00000004
    OWNER              = 0x00000008
    USE_FOR_DENY_ONLY  = 0x00000010
    INTEGRITY          = 0x00000020
    INTEGRITY_ENABLED  = 0x00000040
    RESOURCE           = 0x20000000
    LOGON_ID           = 3221225472
} -Bitfield

$SE_PRIVILEGE = psenum $Module SE_PRIVILEGE UInt32 @{
    DISABLED           = 0x00000000
    ENABLED_BY_DEFAULT = 0x00000001
    ENABLED            = 0x00000002
    REMOVED            = 0x00000004
    USED_FOR_ACCESS    = 2147483648
} -Bitfield

$SECURITY_IMPERSONATION_LEVEL = psenum $Module SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous      = 0
    SecurityIdentification = 1
    SecurityImpersonation  = 2
    SecurityDelegation     = 3
}

$SECURITY_LOGON_TYPE = psenum $Module SECURITY_LOGON_TYPE UInt32 @{
    System                  = 0
    Interactive             = 2
    Network                 = 3
    Batch                   = 4
    Service                 = 5
    Proxy                   = 6
    Unlock                  = 7
    NetworkCleartext        = 8
    NewCredentials          = 9
    RemoteInteractive       = 10
    CachedInteractive       = 11
    CachedRemoteInteractive = 12
    CachedUnlock            = 13
}

$SecurityEntity = psenum $Module SecurityEntity UInt32 @{
    SeCreateTokenPrivilege          = 1
    SeAssignPrimaryTokenPrivilege   = 2
    SeLockMemoryPrivilege           = 3
    SeIncreaseQuotaPrivilege        = 4
    SeUnsolicitedInputPrivilege     = 5
    SeMachineAccountPrivilege       = 6
    SeTcbPrivilege                  = 7
    SeSecurityPrivilege             = 8
    SeTakeOwnershipPrivilege        = 9
    SeLoadDriverPrivilege           = 10
    SeSystemProfilePrivilege        = 11
    SeSystemtimePrivilege           = 12
    SeProfileSingleProcessPrivilege = 13
    SeIncreaseBasePriorityPrivilege = 14
    SeCreatePagefilePrivilege       = 15
    SeCreatePermanentPrivilege      = 16
    SeBackupPrivilege               = 17
    SeRestorePrivilege              = 18
    SeShutdownPrivilege             = 19
    SeDebugPrivilege                = 20
    SeAuditPrivilege                = 21
    SeSystemEnvironmentPrivilege    = 22
    SeChangeNotifyPrivilege         = 23
    SeRemoteShutdownPrivilege       = 24
    SeUndockPrivilege               = 25
    SeSyncAgentPrivilege            = 26
    SeEnableDelegationPrivilege     = 27
    SeManageVolumePrivilege         = 28
    SeImpersonatePrivilege          = 29
    SeCreateGlobalPrivilege         = 30
    SeTrustedCredManAccessPrivilege = 31
    SeRelabelPrivilege              = 32
    SeIncreaseWorkingSetPrivilege   = 33
    SeTimeZonePrivilege             = 34
    SeCreateSymbolicLinkPrivilege   = 35
}

$THREAD_ACCESS = psenum $Module THREAD_ACCESS UInt32 @{
    THREAD_TERMINATE                 = 0x00000001
    THREAD_SUSPEND_RESUME            = 0x00000002
    THREAD_GET_CONTEXT               = 0x00000008
    THREAD_SET_CONTEXT               = 0x00000010
    THREAD_SET_INFORMATION           = 0x00000020
    THREAD_QUERY_INFORMATION         = 0x00000040
    THREAD_SET_THREAD_TOKEN          = 0x00000080
    THREAD_IMPERSONATE               = 0x00000100
    THREAD_DIRECT_IMPERSONATION      = 0x00000200
    THREAD_SET_LIMITED_INFORMATION   = 0x00000400
    THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
    DELETE                           = 0x00010000
    READ_CONTROL                     = 0x00020000
    WRITE_DAC                        = 0x00040000
    WRITE_OWNER                      = 0x00080000
    SYNCHRONIZE                      = 0x00100000
    THREAD_ALL_ACCESS                = 0x001f0ffb
} -Bitfield

$THREADINFOCLASS = psenum $Module THREADINFOCLASS UInt32 @{
    ThreadBasicInformation          = 1
    ThreadTimes                     = 2
    ThreadPriority                  = 3
    ThreadBasePriority              = 4
    ThreadAffinityMask              = 5
    ThreadImpersonationToken        = 6
    ThreadDescriptorTableEntry      = 7
    ThreadEnableAlignmentFaultFixup = 8
    ThreadEventPair_Reusable        = 9
    ThreadQuerySetWin32StartAddress = 10
    ThreadZeroTlsCell               = 11
    ThreadPerformanceCount          = 12
    ThreadAmILastThread             = 13
    ThreadIdealProcessor            = 14
    ThreadPriorityBoost             = 15
    ThreadSetTlsArrayAddress        = 16
    ThreadIsIoPending               = 17
    ThreadHideFromDebugger          = 18
    ThreadBreakOnTermination        = 19
    ThreadSwitchLegacyState         = 20
    ThreadIsTerminated              = 21
    ThreadLastSystemCall            = 22
    ThreadIoPriority                = 23
    ThreadCycleTime                 = 24
    ThreadPagePriority              = 25
    ThreadActualBasePriority        = 26
    ThreadTebInformation            = 27
    ThreadCSwitchMon                = 28
    ThreadCSwitchPmu                = 29
    ThreadWow64Context              = 30
    ThreadGroupInformation          = 31
    ThreadUmsInformation            = 32
    ThreadCounterProfiling          = 33
    ThreadIdealProcessorEx          = 34
    ThreadCpuAccountingInformation  = 35
    ThreadSuspendCount              = 36
    ThreadHeterogeneousCpuPolicy    = 37
    ThreadContainerId               = 38
    ThreadNameInformation           = 39
    ThreadSelectedCpuSets           = 40
    ThreadSystemThreadInformation   = 41
    ThreadActualGroupAffinity       = 42
    ThreadDynamicCodePolicyInfo     = 43
    ThreadExplicitCaseSensitivity   = 44
    ThreadWorkOnBehalfTicket        = 45
    ThreadSubsystemInformation      = 46
    ThreadDbgkWerReportActive       = 47
    ThreadAttachContainer           = 48
    MaxThreadInfoClass              = 49
}

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
} -Bitfield

$TOKEN_ELEVATION_TYPE = psenum $Module TOKEN_ELEVATION_TYPE UInt32 @{ 
    TokenElevationTypeDefault = 1
    TokenElevationTypeFull    = 2
    TokenElevationTypeLimited = 3
}

$TOKEN_INFORMATION_CLASS = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{ 
    TokenUser                            = 1
    TokenGroups                          = 2
    TokenPrivileges                      = 3
    TokenOwner                           = 4
    TokenPrimaryGroup                    = 5
    TokenDefaultDacl                     = 6
    TokenSource                          = 7
    TokenType                            = 8
    TokenImpersonationLevel              = 9
    TokenStatistics                      = 10
    TokenRestrictedSids                  = 11
    TokenSessionId                       = 12
    TokenGroupsAndPrivileges             = 13
    TokenSessionReference                = 14
    TokenSandBoxInert                    = 15
    TokenAuditPolicy                     = 16
    TokenOrigin                          = 17
    TokenElevationType                   = 18
    TokenLinkedToken                     = 19
    TokenElevation                       = 20
    TokenHasRestrictions                 = 21
    TokenAccessInformation               = 22
    TokenVirtualizationAllowed           = 23
    TokenVirtualizationEnabled           = 24
    TokenIntegrityLevel                  = 25
    TokenUIAccess                        = 26
    TokenMandatoryPolicy                 = 27
    TokenLogonSid                        = 28
    TokenIsAppContainer                  = 29
    TokenCapabilities                    = 30
    TokenAppContainerSid                 = 31
    TokenAppContainerNumber              = 32
    TokenUserClaimAttributes             = 33
    TokenDeviceClaimAttributes           = 34
    TokenRestrictedUserClaimAttributes   = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups                    = 37
    TokenRestrictedDeviceGroups          = 38
    TokenSecurityAttributes              = 39
    TokenIsRestricted                    = 40
    MaxTokenInfoClass                    = 41
}

$TOKENMANDATORYPOLICY = psenum $Module TOKENMANDATORYPOLICY UInt32 @{
    OFF                    = 0x0
    NO_WRITE_UP            = 0x1
    POLICY_NEW_PROCESS_MIN = 0x2
    POLICY_VALID_MASK      = 0x3
}

$TOKEN_TYPE = psenum $Module TOKEN_TYPE UInt32 @{
    TokenPrimary       = 1
    TokenImpersonation = 2
}

#endregion Enums

#region Structs

$ACL = struct $Module ACL @{
    AclRevision = field 0 Byte
    Sbz1        = field 1 Byte
    AclSize     = field 2 UInt16
    AceCount    = field 3 UInt16
    Sbz2        = field 4 UInt16
}

$LSA_LAST_INTER_LOGON_INFO = struct $Module LSA_LAST_INTER_LOGON_INFO @{
    LastSuccessfulLogon = field 0 Int64
    LastFailedLogon = field 1 Int64
    FailedAttemptCountSinceLastSuccessfulLogon = field 2 UInt64
}

$LSA_STRING = struct $Module LSA_STRING @{
    Length = field 0 UInt16
    MaximumLength = field 1 UInt16
    Buffer = field 2 IntPtr
}

$LSA_UNICODE_STRING = struct $Module LSA_UNICODE_STRING @{
    Length = field 0 UInt16
    MaximumLength = field 1 UInt16
    Buffer = field 2 IntPtr
}

$LUID = struct $Module LUID @{
    LowPart  = field 0 $SecurityEntity
    HighPart = field 1 Int32
}

$LUID1 = struct $Module LUID1 @{
    LowPart  = field 0 UInt32
    HighPart = field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LUID_AND_ATTRIBUTES @{
    Luid       = field 0 $LUID
    Attributes = field 1 $SE_PRIVILEGE
}

$MEMORY_BASIC_INFORMATION = struct $Module MEMORY_BASIC_INFORMATION @{
    BaseAddress       = field 0 UIntPtr
    AllocationBase    = field 1 UIntPtr
    AllocationProtect = field 2 $MEMORY_PROTECTION
    RegionSize        = field 3 UIntPtr
    State             = field 4 $MEMORY_STATE
    Protect           = field 5 $MEMORY_PROTECTION
    Type              = field 6 $MEMORY_TYPE
}

$SecHandle = struct $Module SecHandle @{
    dwLower = field 0 IntPtr       
    dwUpper = field 1 IntPtr
}

$SECURITY_LOGON_SESSION_DATA = struct $Module SECURITY_LOGON_SESSION_DATA @{
    Size = field 0 UInt32
    LogonId = field 1 $LUID
    Username = field 2 $LSA_UNICODE_STRING
    LogonDomain = field 3 $LSA_UNICODE_STRING
    AuthenticationPackage = field 4 $LSA_UNICODE_STRING
    LogonType = field 5 $SECURITY_LOGON_TYPE
    Session = field 6 UInt32
    PSiD = field 7 IntPtr
    LogonTime = field 8 UInt64
    LogonServer = field 9 $LSA_UNICODE_STRING
    DnsDomainName = field 10 $LSA_UNICODE_STRING
    Upn = field 11 $LSA_UNICODE_STRING
    UserFlags = field 12 UInt64
    LastLogonInfo = field 13 $LSA_LAST_INTER_LOGON_INFO
    LogonScript = field 14 $LSA_UNICODE_STRING
    ProfilePath = field 15 $LSA_UNICODE_STRING
    HomeDirectory = field 16 $LSA_UNICODE_STRING
    HomeDirectoryDrive = field 17 $LSA_UNICODE_STRING
    LogoffTime = field 18 Int64
    KickOffTime = field 19 Int64
    PasswordLastSet = field 20 Int64
    PasswordCanChange = field 21 Int64
    PasswordMustChange = field 22 Int64
}

$SID_AND_ATTRIBUTES = struct $Module SID_AND_ATTRIBUTES @{
    Sid        = field 0 IntPtr
    Attributes = field 1 $SE_GROUP
} -PackingSize Size8

$TOKEN_APPCONTAINER_INFORMATION = struct $Module TOKEN_APPCONSTAINER_INFORMATION @{
    TokenAppContainer = field 0 IntPtr
}

$TOKEN_DEFAULT_DACL = struct $Module TOKEN_DEFAULT_DACL @{
    DefaultDacl = field 0 $ACL
}

$TOKEN_ELEVATION = struct $Module TOKEN_ELEVATION @{
    TokenIsElevated = field 0 UInt32
}

$TOKEN_GROUPS = struct $Module TOKEN_GROUPS @{
    GroupCount = field 0 UInt32
    Groups     = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs ('ByValArray', 50)
}

$TOKEN_GROUPS_AND_PRIVILEGES = struct $Module TOKEN_GROUPS_AND_PRIVILEGES @{
    SidCount            = field 0 UInt32
    SidLength           = field 1 UInt32
    Sids                = field 2 IntPtr
    RestrictedSidCount  = field 3 UInt32
    RestrictedSidLength = field 4 UInt32
    RestrictedSids      = field 5 IntPtr
    PrivilegeCount      = field 6 UInt32
    PrivilegeLength     = field 7 UInt32
    Privileges          = field 8 IntPtr
    AuthenticationId    = field 9 $LUID
}

$TOKEN_LINKED_TOKEN = struct $Module TOKEN_LINKED_TOKEN @{
    LinkedToken = field 0 IntPtr
}

$TOKEN_MANDATORY_LABEL = struct $Module TOKEN_MANDATORY_LABEL @{
    Label = field 0 $SID_AND_ATTRIBUTES
}

$TOKEN_MANDATORY_POLICY = struct $Module TOKEN_MANDATORY_POLICY @{
    Policy = field 0 $TOKENMANDATORYPOLICY
}

$TOKEN_OWNER = struct $Module TOKEN_OWNER @{
    Owner = field 0 IntPtr
}

$TOKEN_PRIVILEGES = struct $Module TOKEN_PRIVILEGES @{
    PrivilegeCount = field 0 UInt32
    Privileges     = field 1  $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_SOURCE = struct $Module TOKEN_SOURCE @{
    SourceName       = field 0 string
    SourceIdentifier = field 1 $LUID
}

$TOKEN_STATISTICS = struct $Module TOKEN_STATISTICS @{
    TokenId            = field 0 $LUID
    AuthenticationId   = field 1 $LUID
    ExpirationTime     = field 2 UInt64
    TokenType          = field 3 $TOKEN_TYPE
    ImpersonationLevel = field 4 $SECURITY_IMPERSONATION_LEVEL
    DynamicCharged     = field 5 UInt32
    DynamicAvailable   = field 6 UInt32
    GroupCount         = field 7 UInt32
    PrivilegeCount     = field 8 UInt32
    ModifiedId         = field 9 $LUID
}

$TOKEN_USER = struct $Module TOKEN_USER @{
    User = field 0 $SID_AND_ATTRIBUTES
}

$KERB_CRYPTO_KEY = struct $Module KERB_CRYPTO_KEY @{
    KeyType = field 0 Int32
    Length = field 1 Int32
    Value = field 2 IntPtr
}

$KERB_EXTERNAL_NAME = struct $Module KERB_EXTERNAL_NAME @{
    NameType = field 0 Int16
    NameCount = field 1 UInt16
    Names = field 2 $LSA_UNICODE_STRING
}

$KERB_EXTERNAL_TICKET = struct $Module KERB_EXTERNAL_TICKET @{
    ServiceName = field 0 IntPtr
    TargetName = field 1 IntPtr
    ClientName = field 2 IntPtr
    DomainName = field 3 $LSA_UNICODE_STRING
    TargetDomainName = field 4 $LSA_UNICODE_STRING
    AltTargetDomainName = field 5 $LSA_UNICODE_STRING
    SessionKey = field 6 $KERB_CRYPTO_KEY
    TicketFlags = field 7 UInt32
    Flags = field 8 UInt32
    KeyExpirationTime = field 9 Int64
    StartTime = field 10 Int64
    EndTime = field 11 Int64
    RenewUntil = field 12 Int64
    TimeSkew = field 13 Int64
    EncodedTicketSize = field 14 Int32
    EncodedTicket = field 15 IntPtr
}

$KERB_RETRIEVE_TKT_REQUEST = struct $Module KERB_RETRIEVE_TKT_REQUEST @{
    MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
    LogonId = field 1 $LUID1
    TargetName = field 2 $LSA_UNICODE_STRING
    TicketFlags = field 3 UInt64
    CacheOptions = field 4 $KERB_CACHE_OPTIONS
    EncryptionType = field 5 Int64
    CredentialsHandle = field 6 $SecHandle
}

$KERB_RETRIEVE_TKT_RESPONSE = struct $Module KERB_RETRIEVE_TKT_RESPONSE @{
    Ticket = field 0 $KERB_EXTERNAL_TICKET
}

#endregion Structs

#region Function Definitions

$FunctionDefinitions = @(
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr] #_In_ HANDLE hObject
    ) -EntryPoint CloseHandle -SetLastError),

    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                 #_In_  PSID   Sid,
        [IntPtr].MakeByRefType() #_Out_ LPTSTR *StringSid
    ) -EntryPoint ConvertSidToStringSid -SetLastError),

    (func advapi32 DuplicateToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE                       ExistingTokenHandle,
        [UInt32],                #_In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        [IntPtr].MakeByRefType() #_Out_ PHANDLE                      DuplicateTokenHandle
    ) -EntryPoint DuplicateToken -SetLastError),

    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],                #_In_      HANDLE                  TokenHandle
        [Int32],                 #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
        [IntPtr],                #_Out_opt_ LPVOID                  TokenInformation
        [UInt32],                #_In_      DWORD                   TokenInformationLength
        [UInt32].MakeByRefType() #_Out_     PDWORD                  ReturnLength
    ) -EntryPoint GetTokenInformation -SetLastError),

    (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
        [IntPtr] #_In_ HANDLE hToken
    ) -EntryPoint ImpersonateLoggedOnUser -SetLastError),

    (func secur32 LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT ([UInt32]) @(
        [IntPtr],                                   #_In_  HANDLE    LsaHandle
        [UInt64],                                   #_In_  ULONG     AuthenticationPackage
        $KERB_RETRIEVE_TKT_REQUEST.MakeByRefType(), #_In_  PVOID     ProtocolSubmitBuffer
        [UInt64],                                   #_In_  ULONG     SubmitBufferLength
        [IntPtr].MakeByRefType(),#_Out_ PVOID     *ProtocolReturnBuffer
        [UInt64].MakeByRefType(),                   #_Out_ PULONG    *ReturnBufferLength
        [UInt32].MakeByRefType()                    #_Out_ PNTSTATUS ProtocolStatus
    ) -EntryPoint LsaCallAuthenticationPackage),

    (func secur32 LsaDeregisterLogonProcess ([UInt32]) @(
        [IntPtr] #_In_ HANDLE LsaHandle
    ) -EntryPoint LsaDeregisterLogonProcess),

    (func secur32 LsaEnumerateLogonSessions ([UInt32]) @(
        [UInt64].MakeByRefType(), #_Out_ PULONG LogonSessionCount,
        [IntPtr].MakeByRefType()  #_Out_ PLUID  *LogonSessionList
    ) -EntryPoint LsaEnumerateLogonSessions),
    
    (func secur32 LsaFreeReturnBuffer ([UInt32]) @(
        [IntPtr].MakeByRefType()  #_In_ PVOID Buffer
    ) -EntryPoint LsaFreeReturnBuffer),
    
    (func secur32 LsaGetLogonSessionData ([UInt32]) @(
        [IntPtr],                 #_In_  PLUID                        LogonId,
        [IntPtr].MakeByRefType()  #_Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
    ) -EntryPoint LsaGetLogonSessionData),

    (func secur32 LsaLookupAuthenticationPackage ([UInt32]) @(
        [IntPtr],                               #_In_  HANDLE      LsaHandle,
        $LSA_STRING.MakeByRefType()             #_In_  PLSA_STRING PackageName,
        [UInt64].MakeByRefType()                #_Out_ PULONG      AuthenticationPackage
    ) -EntryPoint LsaLookupAuthenticationPackage),
            
    (func advapi32 LsaNtStatusToWinError ([UInt64]) @(
        [UInt32] #_In_ NTSTATUS Status
    ) -EntryPoint LsaNtStatusToWinError),

    (func secur32 LsaRegisterLogonProcess ([UInt32]) @(
        $LSA_STRING.MakeByRefType() #_In_  PLSA_STRING           LogonProcessName,
        [IntPtr].MakeByRefType()    #_Out_ PHANDLE               LsaHandle,
        [UInt64].MakeByRefType()    #_Out_ PLSA_OPERATIONAL_MODE SecurityMode
    ) -EntryPoint LsaRegisterLogonProcess),

    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr], #_In_      HANDLE          ThreadHandle,
        [Int32],  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr], #_Inout_   PVOID           ThreadInformation,
        [Int32],  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]  #_Out_opt_ PULONG          ReturnLength
    ) -EntryPoint NtQueryInformationThread),

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwProcessId
    ) -EntryPoint OpenProcess -SetLastError),

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError),

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwThreadId
    ) -EntryPoint OpenThread -SetLastError),

    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                #_In_  HANDLE  ThreadHandle
      [UInt32],                #_In_  DWORD   DesiredAccess
      [bool],                  #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenThreadToken -SetLastError),

    (func advapi32 RevertToSelf ([bool]) @(
        # No Parameters
    ) -EntryPoint RevertToSelf -SetLastError),

    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORY_BASIC_INFORMATION.MakeByRefType(), #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -EntryPoint VirtualQueryEx -SetLastError)
)

#endregion Function Definitions

#region Windows API Functions

function CloseHandle
{
    <#
    .SYNOPSIS

    Closes an open object handle.

    .DESCRIPTION

    The CloseHandle function closes handles to the following objects:
    - Access token
    - Communications device
    - Console input
    - Console screen buffer
    - Event
    - File
    - File mapping
    - I/O completion port
    - Job
    - Mailslot
    - Memory resource notification
    - Mutex
    - Named pipe
    - Pipe
    - Process
    - Semaphore
    - Thread
    - Transaction
    - Waitable timer
    
    The documentation for the functions that create these objects indicates that CloseHandle should be used when you are finished with the object, and what happens to pending operations on the object after the handle is closed. In general, CloseHandle invalidates the specified object handle, decrements the object's handle count, and performs object retention checks. After the last handle to an object is closed, the object is removed from the system. 

    .PARAMETER Handle

    A valid handle to an open object.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None
    
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr] #_In_ HANDLE hObject
    ) -EntryPoint CloseHandle -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Handle    
    )
    
    $SUCCESS = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $SUCCESS) 
    {
        Write-Debug "CloseHandle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function ConvertSidToStringSid
{
    <#
    .SYNOPSIS

    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.

    .DESCRIPTION

    The ConvertSidToStringSid function uses the standard S-R-I-S-S… format for SID strings.
    
    .PARAMETER SidPointer

    A pointer to the SID structure to be converted.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None
    
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                 #_In_  PSID   Sid,
        [IntPtr].MakeByRefType() #_Out_ LPTSTR *StringSid
    ) -EntryPoint ConvertSidToStringSid -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa376399(v=vs.85).aspx

    .EXAMPLE
    #>

    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer    
    )
    
    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Verbose "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}

function DuplicateToken
{
    <#
    .SYNOPSIS

    The DuplicateToken function creates a new access token that duplicates one already in existence.

    .DESCRIPTION

    The DuplicateToken function creates an impersonation token, which you can use in functions such as SetThreadToken and ImpersonateLoggedOnUser. The token created by DuplicateToken cannot be used in the CreateProcessAsUser function, which requires a primary token. To create a token that you can pass to CreateProcessAsUser, use the DuplicateTokenEx function.

    .PARAMETER TokenHandle

    A handle to an access token opened with TOKEN_DUPLICATE access.

    .PARAMETER ImpersonationLevel

    Specifies a SECURITY_IMPERSONATION_LEVEL enumerated type that supplies the impersonation level of the new token. The Default is SecurityImpersonation.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, SECURITY_IMPERSONATION_LEVEL (Enumeration)
    Optional Dependencies: None

    (func advapi32 DuplicateToken ([bool]) @(
        [IntPtr]                 #_In_  HANDLE                       ExistingTokenHandle,
        [UInt32]                 #_In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        [IntPtr].MakeByRefType() #_Out_ PHANDLE                      DuplicateTokenHandle
    ) -EntryPoint DuplicateToken -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa446616(v=vs.85).aspx

    .EXAMPLE

    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,

        [Parameter()]
        [ValidateSet('None','SecurityAnonymous','SecurityIdentification','SecurityImpersonation','SecurityDelegation')]
        [string]
        $ImpersonationLevel = 'SecurityImpersonation'
    )

    $DuplicateTokenHandle = [IntPtr]::Zero

    $success = $Advapi32::DuplicateToken($TokenHandle, $SECURITY_IMPERSONATION_LEVEL::$ImpersonationLevel, [ref]$DuplicateTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $success)
    {
        Write-Debug "DuplicateToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $DuplicateTokenHandle
}

function GetTokenInformation
{
    <#
    .SYNOPSIS

    The GetTokenInformation function retrieves a specified type of information about an access token. The calling process must have appropriate access rights to obtain the information.
    
    To determine if a user is a member of a specific group, use the CheckTokenMembership function. To determine group membership for app container tokens, use the CheckTokenMembershipEx function.

    .PARAMETER TokenHandle

    A handle to an access token from which information is retrieved. If TokenInformationClass specifies TokenSource, the handle must have TOKEN_QUERY_SOURCE access. For all other TokenInformationClass values, the handle must have TOKEN_QUERY access.

    .PARAMETER TokenInformationClass

    Specifies a value from the TOKEN_INFORMATION_CLASS enumerated type to identify the type of information the function retrieves. Any callers who check the TokenIsAppContainer and have it return 0 should also verify that the caller token is not an identify level impersonation token. If the current token is not an app container but is an identity level token, you should return AccessDenied.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Module Dependencies: PSReflect
    Required Function Dependencies: ConvertSidToStringSid
    Required Structure Dependencies: TOKEN_USER, SID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, TOKEN_OWNER, TOKEN_SOURCE, LUID, TOKEN_MANDATORY_LABEL
    Required Enumeration Dependencies: LuidAttributes, TOKEN_TYPE, SECURITY_IMPERSONATION_LEVEL
    Optional Dependencies: TokenInformationClass (Enum)

    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],                #_In_      HANDLE                  TokenHandle
        [Int32],                 #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
        [IntPtr],                #_Out_opt_ LPVOID                  TokenInformation
        [UInt32],                #_In_      DWORD                   TokenInformationLength
        [UInt32].MakeByRefType() #_Out_     PDWORD                  ReturnLength
    ) -EntryPoint GetTokenInformation -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TokenUser','TokenGroups','TokenPrivileges','TokenOwner','TokenPrimaryGroup','TokenDefaultDacl','TokenSource','TokenType','TokenImpersonationLevel','TokenStatistics','TokenRestrictedSids','TokenSessionId','TokenGroupsAndPrivileges','TokenSessionReference','TokenSandBoxInert','TokenOrigin','TokenElevationType','TokenLinkedToken','TokenElevation','TokenHasRestrictions','TokenAccessInformation','TokenVirtualizationAllowed','TokenVirtualizationEnabled','TokenIntegrityLevel','TokenUIAccess','TokenMandatoryPolicy','TokenLogonSid','TokenIsAppContainer','TokenCapabilities','TokenAppContainerSid','TokenAppContainerNumber','TokenUserClaimAttributes','TokenDeviceClaimAttributes','TokenDeviceGroups','TokenRestrictedDeviceGroups')]
        [string]
        $TokenInformationClass
    )

    # initial query to determine the necessary buffer size
    $TokenPtrSize = 0
    $SUCCESS = $Advapi32::GetTokenInformation($TokenHandle, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, [IntPtr]::Zero, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)

    # retrieve the proper buffer value
    $SUCCESS = $Advapi32::GetTokenInformation($TokenHandle, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS)
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
        throw "GetTokenInformation Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    switch($TokenInformationClass)
    {
        TokenUser
        {
            <#
            The buffer receives a TOKEN_USER structure that contains the user account of the token.
                ConvertSidToStringSid (Function)
                TOKEN_USER (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenUser = $TokenPtr -as $TOKEN_USER
            $UserSid = ConvertSidToStringSid -SidPointer $TokenUser.User.Sid

            $Sid = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
            $UserName = $Sid.Translate([System.Security.Principal.NTAccount])

            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name Sid -Value $UserSid
            $obj | Add-Member -MemberType NoteProperty -Name Name -Value $UserName

            Write-Output $obj
        }
        TokenGroups
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenPrivileges
        {
            <#
            The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
                TOKEN_PRIVILEGES (Structure)
                LUID_AND_ATTRIBUTES (Structure)
                LuidAttributes (Enumeration)
            #>
            $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES
                
            for($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++)
            {
                $obj = New-Object -TypeName psobject
                    
                $obj | Add-Member -MemberType NoteProperty -Name Privilege -Value $TokenPrivileges.Privileges[$i].Luid.LowPart
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenPrivileges.Privileges[$i].Attributes
                    
                Write-Output $obj   
            }

        }
        TokenOwner
        {
            <#
            The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
                ConvertSidToStringSid (Function)
                TOKEN_OWNER (Structure)
            #>
            $TokenOwner = $TokenPtr -as $TOKEN_OWNER
    
            if($TokenOwner.Owner -ne $null)
            {
                $OwnerSid = ConvertSidToStringSid -SidPointer $TokenOwner.Owner
                
                $Sid = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)
                $OwnerName = $Sid.Translate([System.Security.Principal.NTAccount])

                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value $OwnerSid
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $OwnerName

                Write-Output $obj
            }
            else
            {
                Write-Output $null
            }
        }
        TokenPrimaryGroup
        {
            <#
            The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
                TOKEN_PRIMARY_GROUP (Structure)
            #>
            throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenDefaultDacl
        {
            <#
            The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
                TOKEN_DEFAULT_DACL (Structure)
                ACL (Structure)
            #>
            $Dacl = $TokenPtr -as $TOKEN_DEFAULT_DACL
            Write-Output $Dacl.DefaultDacl
        }
        TokenSource
        {
            <#
            The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
                TOKEN_SOURCE (Structure)
                LUID (Structure)
            #>
            
            Write-Output $TokenPtr
            #$TokenSource = $TokenPtr -as $TOKEN_SOURCE
            #Write-Output ($TokenSource.SourceName -join "")
        }
        TokenType
        {
            <#
            The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
                TOKEN_TYPE (Enumeration)
            #>
            if($TokenPtr -ne $null)
            {
                Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr) -as $TOKEN_TYPE)
            }
        }
        TokenImpersonationLevel
        {
            <#
            The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
                SECURITY_IMPERSONATION_LEVEL (Enumeration)
            #>
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr) -as $SECURITY_IMPERSONATION_LEVEL)
        }
        TokenStatistics
        {
            <#
            The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
                TOKEN_STATISTICS (Structure)
                LUID (Structure)
                TOKEN_TYPE (Enumeration)
                SECURITY_IMPERSONATION_LEVEL (Enumeration)
            #>
            $TokenStats = $TokenPtr -as $TOKEN_STATISTICS

            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name TokenId -Value $TokenStats.TokenId.LowPart
            $obj | Add-Member -MemberType NoteProperty -Name AuthenticationId -Value $TokenStats.AuthenticationId.LowPart
            $obj | Add-Member -MemberType NoteProperty -Name TokenType -Value $TokenStats.TokenType
            $obj | Add-Member -MemberType NoteProperty -Name ImpersonationLevel -Value $TokenStats.ImpersonationLevel
            $obj | Add-Member -MemberType NoteProperty -Name DynamicCharged -Value $TokenStats.DynamicCharged
            $obj | Add-Member -MemberType NoteProperty -Name DynamicAvailable -Value $TokenStats.DynamicAvailable
            $obj | Add-Member -MemberType NoteProperty -Name GroupCount -Value $TokenStats.GroupCount
            $obj | Add-Member -MemberType NoteProperty -Name PrivilegeCount -Value $TokenStats.PrivilegeCount
            $obj | Add-Member -MemberType NoteProperty -Name ModifiedId -Value $TokenStats.ModifiedId.LowPart
                
            Write-Output $obj
        }
        TokenRestrictedSids
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenSessionId
        {
            # The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            # If the token is associated with the terminal server client session, the session identifier is nonzero.
            # Windows Server 2003 and Windows XP:  If the token is associated with the terminal server console session, the session identifier is zero.
            # In a non-Terminal Services environment, the session identifier is zero.
            # If TokenSessionId is set with SetTokenInformation, the application must have the Act As Part Of the Operating System privilege, and the application must be enabled to set the session ID in a token.
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr))
        }
        TokenGroupsAndPrivileges
        {
            <#
            The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
                TOKEN_GROUPS_AND_PRIVILEGES (Structure)
                SID_AND_ATTRIBUTES (Structure)
                LUID (Structure)
            #>
            $GroupsAndPrivs = ($TokenPtr -as $TOKEN_GROUPS_AND_PRIVILEGES)
                
            $SidList = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

            for($i = 0; $i -lt $GroupsAndPrivs.SidCount; $i++)
            {
                $currentPtr = [IntPtr]($GroupsAndPrivs.Sids.ToInt64() + ($SID_AND_ATTRIBUTES::GetSize() * $i))
                $SidAndAttr = $currentPtr -as $SID_AND_ATTRIBUTES

                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $SidAndAttr.Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $SidAndAttr.Attributes

                $SidList.Add($obj)
            }
                
            $PrivList = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

            for($i = 0; $i -lt $GroupsAndPrivs.PrivilegeCount; $i++)
            {
                $currentPtr = [IntPtr]($GroupsAndPrivs.Privileges.ToInt64() + ($LUID_AND_ATTRIBUTES::GetSize() * $i))
                $LuidAndAttr = ($currentPtr -as $LUID_AND_ATTRIBUTES)

                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Privilege -Value $LuidAndAttr.Luid.LowPart
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $LuidAndAttr.Attributes

                $PrivList.Add($obj)
            }

            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name Sids -Value $SidList.ToArray()
            $obj | Add-Member -MemberType NoteProperty -Name Privilegs -Value $PrivList.ToArray()

            Write-Output $obj
        }
        TokenSessionReference
        {
            Write-Output $TokenPtr
        }
        TokenSandBoxInert
        {
            # The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenOrigin
        {
            <#
            The buffer receives a TOKEN_ORIGIN value.
            If the token resulted from a logon that used explicit credentials, such as passing a name, domain, and password to the LogonUser function, then the TOKEN_ORIGIN structure will contain the ID of the logon session that created it.
            If the token resulted from network authentication, such as a call to AcceptSecurityContext or a call to LogonUser with dwLogonType set to LOGON32_LOGON_NETWORK or LOGON32_LOGON_NETWORK_CLEARTEXT, then this value will be zero.
                TOKEN_ORIGIN (Structure)
                LUID (Structure)
            #>
            $TokenOrigin = $TokenPtr -as $LUID
            Write-Output $TokenOrigin.LowPart
        }
        TokenElevationType
        {
            <#
            The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
                TOKEN_ELEVATION_TYPE (Enumeration)
            #>
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr) -as $TOKEN_ELEVATION_TYPE)
        }
        TokenLinkedToken
        {
            <#
            The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
                TOKEN_LINKED_TOKEN (Structure)
            #>
            Write-Output ($TokenPtr -as $TOKEN_LINKED_TOKEN).LinkedToken
        }
        TokenElevation
        {
            <#
            The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.                                    
                TOKEN_ELEVATION (Structure)
            #>
            Write-Output (($TokenPtr -as $TOKEN_ELEVATION).TokenIsElevated -ne 0)
        }
        TokenHasRestrictions
        {
            # The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenAccessInformation
        {
            <#
            The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
                TOKEN_ACCESS_INFORMATION (Structure)
                SID_AND_ATTRIBUTES_HASH (Structure)
                SID_HASH_ENTRY (Structure)
                TOKEN_PRIVILEGES (Structure)
                LUID_AND_ATTRIBUTES (Structure)
                LUID (Structure)
                TOKEN_TYPE (Enumeration)
                SECURITY_IMPERSONATION_LEVEL (Enumeration)
                TOKEN_MANDATORY_POLICY (Structure)
            #>
            <#
            $TokenAccessInfo = ($TokenPtr -as $TOKEN_ACCESS_INFORMATION)
                
            $obj = New-Object -TypeName psobject

            $obj | Add-Member -MemberType NoteProperty -Name SidHash -Value ($TokenAccessInfo.SidHash -as $SID_AND_ATTRIBUTES_HASH)
            $obj | Add-Member -MemberType NoteProperty -Name RestrictedSidHash -Value ($TokenAccessInfo.RestrictedSidHash -as $SID_AND_ATTRIBUTES_HASH)
            $obj | Add-Member -MemberType NoteProperty -Name Privileges -Value ($TokenAccessInfo.Privileges -as $TOKEN_PRIVILEGES)
            $obj | Add-Member -MemberType NoteProperty -Name AuthenticationId -Value $TokenAccessInfo.AuthenticationId.LowPart
            $obj | Add-Member -MemberType NoteProperty -Name TokenType -Value $TokenAccessInfo.TokenType
            $obj | Add-Member -MemberType NoteProperty -Name ImpersonationLevel -Value $TokenAccessInfo.ImpersonationLevel
            $obj | Add-Member -MemberType NoteProperty -Name AppContainerNumber -Value $TokenAccessInfo.AppContainerNumber
            $obj | Add-Member -MemberType NoteProperty -Name PackageSid -Value (ConvertSidToStringSid -SidPointer $TokenAccessInfo.PackageSid)
            $obj | Add-Member -MemberType NoteProperty -Name CapabilitiesHash -Value ($TokenAccessInfo.CapabilitiesHash -as $SID_AND_ATTRIBUTES_HASH)
            $obj | Add-Member -MemberType NoteProperty -Name TrustLevelSid -Value (ConvertSidToStringSid -SidPointer $TokenAccessInfo.TrustLevelSid)

            Write-Output $obj
            #>

            Write-Output $TokenPtr
            #throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenVirtualizationAllowed
        {
            # The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenVirtualizationEnabled
        {
            # The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenIntegrityLevel
        {
            <#
            The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
                TOKEN_MANDATORY_LABEL
                ConvertSidToStringSid
            #>
            $TokenIntegrity = $TokenPtr -as $TOKEN_MANDATORY_LABEL

            switch(ConvertSidToStringSid -SidPointer $TokenIntegrity.Label.Sid)
            {
                S-1-16-0
                {
                    Write-Output "UNTRUSTED_MANDATORY_LEVEL"
                }
                S-1-16-4096
                {
                    Write-Output "LOW_MANDATORY_LEVEL"
                }
                S-1-16-8192
                {
                    Write-Output "MEDIUM_MANDATORY_LEVEL"
                }
                S-1-16-8448
                {
                    Write-Output "MEDIUM_PLUS_MANDATORY_LEVEL"
                }
                S-1-16-12288
                {
                    Write-Output "HIGH_MANDATORY_LEVEL"
                }
                S-1-16-16384
                {
                    Write-Output "SYSTEM_MANDATORY_LEVEL"
                }
                S-1-16-20480
                {
                    Write-Output "PROTECTED_PROCESS_MANDATORY_LEVEL"
                }
                S-1-16-28672
                {
                    Write-Output "SECURE_PROCESS_MANDATORY_LEVEL"
                }
            }
        }
        TokenUIAccess
        {
            # The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenMandatoryPolicy
        {
            <#
            The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
                TOKEN_MANDATORY_POLICY
                TOKENMANDATORYPOLICY
            #>
            $MandatoryPolicy = $TokenPtr -as $TOKEN_MANDATORY_POLICY
            Write-Output $MandatoryPolicy.Policy
        }
        TokenLogonSid
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that specifies the token's logon SID.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenIsAppContainer
        {
            # The buffer receives a DWORD value that is nonzero if the token is an app container token. Any callers who check the TokenIsAppContainer and have it return 0 should also verify that the caller token is not an identify level impersonation token. If the current token is not an app container but is an identity level token, you should return AccessDenied.
            Write-Output (0 -ne ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr)))
        }
        TokenCapabilities
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the capabilities associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenAppContainerSid
        {
            <#
            The buffer receives a TOKEN_APPCONTAINER_INFORMATION structure that contains the AppContainerSid associated with the token. If the token is not associated with an app container, the TokenAppContainer member of the TOKEN_APPCONTAINER_INFORMATION structure points to NULL.
                TOKEN_APPCONTAINER_INFORMATION (Structure)
            #>
            Write-Output ($TokenPtr -as $TOKEN_APPCONTAINER_INFORMATION)
        }
        TokenAppContainerNumber
        {
            # The buffer receives a DWORD value that includes the app container number for the token. For tokens that are not app container tokens, this value is zero.
            Write-Output ([System.Runtime.InteropServices.Marshal]::ReadInt32($TokenPtr))
        }
        TokenUserClaimAttributes
        {
            <#
            The buffer receives a CLAIM_SECURITY_ATTRIBUTES_INFORMATION structure that contains the user claims associated with the token.
                CLAIM_SECURITY_ATTRIBUTES_INFORMATION (Structure)
                CLAIM_SECURITY_ATTRIBUTE_V1 (Structure)
                CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE (Structure)
                CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE (Structure)
            #>
            <#
            $AttributeInformation = $TokenPtr -as $CLAIM_SECURITY_ATTRIBUTES_INFORMATION
                
            if($AttributeInformation.AttributeCount -ne 0)
            {

            }
            #>
            throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenDeviceClaimAttributes
        {
            <#
            The buffer receives a CLAIM_SECURITY_ATTRIBUTES_INFORMATION structure that contains the device claims associated with the token.
                CLAIM_SECURITY_ATTRIBUTES_INFORMATION (Structure)
                CLAIM_SECURITY_ATTRIBUTE_V1 (Structure)
                CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE (Structure)
                CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE (Structure)
            #>
            <#
            $AttributeInformation = $TokenPtr -as $CLAIM_SECURITY_ATTRIBUTES_INFORMATION
                
            if($AttributeInformation.AttributeCount -ne 0)
            {

            }
            #>
            throw [System.NotImplementedException]"The $($TokenInformationClass) class is not implemented yet."
        }
        TokenDeviceGroups
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the device groups that are associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            #Write-Output ($TokenPtr -as $TOKEN_GROUPS)
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
        TokenRestrictedDeviceGroups
        {
            <#
            The buffer receives a TOKEN_GROUPS structure that contains the restricted device groups that are associated with the token.
                TOKEN_GROUPS (Structure)
                SID_AND_ATTRIBUTES (Structure)
            #>
            $TokenGroups = ($TokenPtr -as $TOKEN_GROUPS)

            for($i = 0; $i -lt $TokenGroups.GroupCount; $i++)
            {
                $obj = New-Object -TypeName psobject

                $obj | Add-Member -MemberType NoteProperty -Name Sid -Value (ConvertSidToStringSid -SidPointer $TokenGroups.Groups[$i].Sid)
                $obj | Add-Member -MemberType NoteProperty -Name Attributes -Value $TokenGroups.Groups[$i].Attributes

                Write-Output $obj
            }
        }
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
}

function ImpersonateLoggedOnUser
{
    <#
    .SYNOPSIS

    The ImpersonateLoggedOnUser function lets the calling thread impersonate the security context of a logged-on user. The user is represented by a token handle.

    .DESCRIPTION

    The impersonation lasts until the thread exits or until it calls RevertToSelf.
    
    The calling thread does not need to have any particular privileges to call ImpersonateLoggedOnUser.
    
    If the call to ImpersonateLoggedOnUser fails, the client connection is not impersonated and the client request is made in the security context of the process. If the process is running as a highly privileged account, such as LocalSystem, or as a member of an administrative group, the user may be able to perform actions they would otherwise be disallowed. Therefore, it is important to always check the return value of the call, and if it fails, raise an error; do not continue execution of the client request.
    
    All impersonate functions, including ImpersonateLoggedOnUser allow the requested impersonation if one of the following is true:
    - The requested impersonation level of the token is less than SecurityImpersonation, such as SecurityIdentification or SecurityAnonymous.
    - The caller has the SeImpersonatePrivilege privilege.
    - A process (or another process in the caller's logon session) created the token using explicit credentials through LogonUser or LsaLogonUser function.
    - The authenticated identity is same as the caller.
    
    Windows XP with SP1 and earlier:  The SeImpersonatePrivilege privilege is not supported.

    .PARAMETER TokenHandle

    A handle to a primary or impersonation access token that represents a logged-on user. This can be a token handle returned by a call to LogonUser, CreateRestrictedToken, DuplicateToken, DuplicateTokenEx, OpenProcessToken, or OpenThreadToken functions. If hToken is a handle to a primary token, the token must have TOKEN_QUERY and TOKEN_DUPLICATE access. If hToken is a handle to an impersonation token, the token must have TOKEN_QUERY and TOKEN_IMPERSONATE access.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
        [IntPtr] #_In_ HANDLE hToken
    ) -EntryPoint ImpersonateLoggedOnUser -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx

    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle
    )

    $SUCCESS = $Advapi32::ImpersonateLoggedOnUser($TokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS)
    {
        throw "ImpersonateLoggedOnUser Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function LsaCallAuthenticationPackage
{
    <#
    .SYNOPSIS

    The LsaCallAuthenticationPackage function is used by a logon application to communicate with an authentication package.
    
    This function is typically used to access services provided by the authentication package.

    .DESCRIPTION

    Logon applications can call LsaCallAuthenticationPackage to communicate with an authentication package. There are several reasons why an application may do this:
    
    - To implement multiple-message authentication protocols, such as the NTLM Challenge-Response protocol.
    - To pass state change information to the authentication package. For example, the NTLM might notify the MSV1_0 package that a previously unreachable domain controller is now reachable. The authentication package would then re-logon any users logged on to that domain controller.
    
    Typically, this function is used to exchange information with a custom authentication package. This function is not needed by an application that is using one of the authentication packages supplied with Windows, such as MSV1_0 or Kerberos.
    
    You must call LsaCallAuthenticationPackage to clean up PKINIT device credentials for LOCAL_SYSTEM and NETWORK_SERVICE. When there is no PKINIT device credential, a successful call does no operation. When there is a PKINIT device credential, a successful call cleans up the PKINIT device credential so that only the password credential remains.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378261(v=vs.85).aspx

    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle,

        [Parameter()]
        [ValidateSet('MICROSOFT_KERBEROS_NAME_A')]
        [string]
        $AuthenticationPackageName = 'MICROSOFT_KERBEROS_NAME_A',

        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId
    )

    <#
    (func secur32 LsaCallAuthenticationPackage ([UInt32]) @(
        [IntPtr],                                  #_In_  HANDLE    LsaHandle
        [UInt64],                                  #_In_  ULONG     AuthenticationPackage
        $KERB_RETRIEVE_TKT_REQUEST.MakeByRefType(),#_In_  PVOID     ProtocolSubmitBuffer
        [UInt64],                                  #_In_  ULONG     SubmitBufferLength
        [IntPtr],                                  #_Out_ PVOID     *ProtocolReturnBuffer
        [UInt64].MakeByRefType(),                  #_Out_ PULONG    *ReturnBufferLength
        [UInt32].MakeByRefType()                   #_Out_ PNTSTATUS ProtocolStatus
    ))
    #>

    $AuthenticationPackage = LsaLookupAuthenticationPackage -LsaHandle $LsaHandle -PackageName $AuthenticationPackageName

    switch($AuthenticationPackageName)
    {
        MICROSOFT_KERBEROS_NAME_A
        {
            $LogonIdLuid = [Activator]::CreateInstance($LUID1)
            $LogonIdLuid.LowPart = $LogonId
            $LogonIdLuid.HighPart = 0


            # Check Ticket Granting Ticket
            <#
            $KERB_RETRIEVE_TKT_REQUEST = struct $Mod Kerberos.KERB_RETRIEVE_TKT_REQUEST @{
                MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
                LogonId = field 1 $LUID
                TargetName = field 2 $LSA_UNICODE_STRING
                TicketFlags = field 3 UInt64
                CacheOptions = field 4 $KERB_CACHE_OPTIONS
                EncryptionType = field 5 Int64
                CredentialsHandle = field 6 IntPtr
            }
            #>

            $ProtocolSubmitBuffer = [Activator]::CreateInstance($KERB_RETRIEVE_TKT_REQUEST)
            $ProtocolSubmitBuffer.MessageType = $KERB_PROTOCOL_MESSAGE_TYPE::KerbRetrieveTicketMessage
            $ProtocolSubmitBuffer.LogonId = $LogonIdLuid

            $ProtocolReturnBuffer = [IntPtr]::Zero
            $ReturnBufferLength = [UInt64]0
            $ProtocolStatus = [UInt32]0

            $SUCCESS = $Secur32::LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT($LsaHandle, $AuthenticationPackage, [ref]$ProtocolSubmitBuffer, $KERB_RETRIEVE_TKT_REQUEST::GetSize(), [ref]$ProtocolReturnBuffer, [ref]$ReturnBufferLength, [ref]$ProtocolStatus)

            if($SUCCESS -eq 0)
            {
                if($ProtocolStatus -eq 0)
                {
                    $data = $ProtocolReturnBuffer -as $KERB_RETRIEVE_TKT_RESPONSE
                    
                    #LsaFreeReturnBuffer -Buffer $ProtocolReturnBuffer

                    $ServiceName_STRING = $data.Ticket.ServiceName -as $KERB_EXTERNAL_NAME
                    $ServiceName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ServiceName_STRING.Names.Buffer, $ServiceName_STRING.Names.Length / 2)
                    #$TargetName_STRING = $data.Ticket.TargetName -as $KERB_EXTERNAL_NAME
                    #$TargetName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($TargetName_STRING.Names.Buffer, $TargetName_STRING.Names.Length / 2)
                    $ClientName_STRING = $data.Ticket.ClientName -as $KERB_EXTERNAL_NAME
                    $ClientName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ClientName_STRING.Names.Buffer, $ClientName_STRING.Names.Length / 2)
                    $DomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.Ticket.DomainName.Buffer, $data.Ticket.DomainName.Length / 2)

                    $TargetDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.Ticket.TargetDomainName.Buffer, $data.Ticket.TargetDomainName.Length / 2)
                    $AltTargetDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.Ticket.AltTargetDomainName.Buffer, $data.Ticket.AltTargetDomainName.Length / 2)
                        
                    # Session Key
                    $SessionKeyType = [string]($data.Ticket.SessionKey.KeyType -as $KERB_ENCRYPTION_TYPE)
                    $SessionKey = New-Object -TypeName byte[]($data.Ticket.SessionKey.Length)
                    [System.Runtime.InteropServices.Marshal]::Copy($data.Ticket.SessionKey.Value, $SessionKey, 0, $data.Ticket.SessionKey.Length)

                    # EncodedTicket Property
                    $EncodedTicket = New-Object -TypeName byte[]($data.Ticket.EncodedTicketSize)
                    [System.Runtime.InteropServices.Marshal]::Copy($data.Ticket.EncodedTicket, $EncodedTicket, 0, $data.Ticket.EncodedTicketSize)

                    $obj = New-Object -TypeName psobject
                    
                    $obj | Add-Member -MemberType NoteProperty -Name ServiceName -Value $ServiceName
                    #$obj | Add-Member -MemberType NoteProperty -Name TargetName -Value $TargetName
                    $obj | Add-Member -MemberType NoteProperty -Name ClientName -Value $ClientName
                    $obj | Add-Member -MemberType NoteProperty -Name DomainName -Value $DomainName
                    $obj | Add-Member -MemberType NoteProperty -Name TargetDomainName -Value $TargetDomainName
                    $obj | Add-Member -MemberType NoteProperty -Name AltTargetDomainName -Value $AltTargetDomainName
                    $obj | Add-Member -MemberType NoteProperty -Name SessionKeyType -Value $SessionKeyType
                    $obj | Add-Member -MemberType NoteProperty -Name SessionKey -Value $SessionKey
                    $obj | Add-Member -MemberType NoteProperty -Name TicketFlags -Value ($data.Ticket.TicketFlags -as $KERB_TICKET_FLAGS).ToString()
                    $obj | Add-Member -MemberType NoteProperty -Name KeyExpirationTime -Value ([datetime]::FromFileTime($data.Ticket.KeyExpirationTime))
                    $obj | Add-Member -MemberType NoteProperty -Name StartTime -Value ([datetime]::FromFileTime($data.Ticket.StartTime))
                    $obj | Add-Member -MemberType NoteProperty -Name EndTime -Value ([datetime]::FromFileTime($data.Ticket.EndTime))
                    $obj | Add-Member -MemberType NoteProperty -Name RenewUntil -Value ([datetime]::FromFileTime($data.Ticket.RenewUntil))
                    $obj | Add-Member -MemberType NoteProperty -Name TimeSkew -Value $data.Ticket.TimeSkew
                    $obj | Add-Member -MemberType NoteProperty -Name EncodedTicketSize -Value $data.Ticket.EncodedTicketSize
                    $obj | Add-Member -MemberType NoteProperty -Name EncodedTicket -Value $EncodedTicket
                    Write-Output $obj
                }
                else
                {
                    
                }                    
            }
            else
            {
                $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
                $LastError = [ComponentModel.Win32Exception]$WinErrorCode
                throw "LsaCallAuthenticationPackage Error: $($LastError.Message)"
            }        
        }
    }
}

function LsaDeregisterLogonProcess
{
    <#
    .SYNOPSIS

    The LsaDeregisterLogonProcess function deletes the caller's logon application context and closes the connection to the LSA server.

    .DESCRIPTION

    If your logon application references the connection handle after calling the LsaDeregisterLogonProcess function, unexpected behavior can result.
    
    .PARAMETER LsaHandle

    Handle obtained from a previous call to LsaRegisterLogonProcess or LsaConnectUntrusted.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, LsaNtStatusToWinError (Function)
    Optional Dependencies: None

    (func secur32 LsaDeregisterLogonProcess ([UInt32]) @(
        [IntPtr] #_In_ HANDLE LsaHandle
    ) -EntryPoint LsaDeregisterLogonProcess)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378269(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaConnectUntrusted

    #
    # Do Somthing with the LSA Handle
    #
    
    LsaDeregisterLogonProcess -LsaHandle $hLsa
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle
    )

    $SUCCESS = $Secur32::LsaDeregisterLogonProcess($LsaHandle)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaDeregisterLogonProcess Error: $($LastError.Message)"
    }
}

function LsaEnumerateLogonSessions
{
    <#
    .SYNOPSIS

    The LsaEnumerateLogonSessions function retrieves the set of existing logon session identifiers (LUIDs) and the number of sessions.

    .DESCRIPTION

    To retrieve information about the logon sessions returned by LsaEnumerateLogonSessions, call the LsaGetLogonSessionData function.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378275(v=vs.85).aspx

    .EXAMPLE

    LsaEnumerateLogonSessions
    8
    2390553591808

    .EXAMPLE

    $SessionCount, $LogonSessionListPtr = LsaEnumerateLogonSessions
    #>

    <#
    (func secur32 LsaEnumerateLogonSessions ([UInt32]) @(
        [UInt64].MakeByRefType(), #_Out_ PULONG LogonSessionCount,
        [IntPtr].MakeByRefType()  #_Out_ PLUID  *LogonSessionList
    ))
    #>

    $LogonSessionCount = [UInt64]0
    $LogonSessionList = [IntPtr]::Zero

    $SUCCESS = $Secur32::LsaEnumerateLogonSessions([ref]$LogonSessionCount, [ref]$LogonSessionList)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaEnumerateLogonSessions Error: $($LastError.Message)"
    }

    return $LogonSessionCount, $LogonSessionList
}

function LsaFreeReturnBuffer
{
    <#
    .SYNOPSIS

    The LsaFreeReturnBuffer function frees the memory used by a buffer previously allocated by the LSA.

    .DESCRIPTION

    Some of the LSA authentication functions allocate memory buffers to hold returned information, for example, LsaLogonUser and LsaCallAuthenticationPackage. Your application should call LsaFreeReturnBuffer to free these buffers when they are no longer needed.


    .PARAMETER Buffer

    Pointer to the buffer to be freed.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378279(v=vs.85).aspx

    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Buffer
    )

    <#
    (func secur32 LsaFreeReturnBuffer ([UInt32]) @(
        [IntPtr].MakeByRefType() #_In_ PVOID Buffer
    ))
    #>

    $SUCCESS = $Secur32::LsaFreeReturnBuffer([ref]$Buffer)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaFreeReturnBuffer Error: $($LastError.Message)"
    }
}
    
function LsaGetLogonSessionData
{
    <#
    .SYNOPSIS

    The LsaGetLogonSessionData function retrieves information about a specified logon session.

    .DESCRIPTION

    .Parameter LuidPtr

    .Parameter SessionCount

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378290(v=vs.85).aspx

    .EXAMPLE

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LuidPtr
    )

    <#
    (func secur32 LsaGetLogonSessionData ([UInt32]) @(
        [IntPtr],                #_In_  PLUID                        LogonId,
        [IntPtr].MakeByRefType() #_Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
    ))
    #>

    function GetDateTimeFromFileTime
    {
        param
        (
            [Parameter(Mandatory = $true)]
            [Int64]
            $FileTime
        )

        if($FileTime -eq [Int64]::MaxValue)
        {
            $datetime = [datetime]::FromFileTime(0)
        }
        else
        {
            $datetime = [datetime]::FromFileTime($FileTime)
        }

        Write-Output $datetime
    }

    $sessionDataPtr = [IntPtr]::Zero
    $SUCCESS = $Secur32::LsaGetLogonSessionData($LuidPtr, [ref]$sessionDataPtr)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $SUCCESS
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaGetLogonSessionData Error: $($LastError.Message)"
    }

    try
    {
        $sessionData = $sessionDataPtr -as $SECURITY_LOGON_SESSION_DATA

        $props = @{
            LogonId = $sessionData.LogonId.LowPart
            UserName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Username.Buffer, $sessionData.Username.Length / 2)
            LogonDomain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonDomain.Buffer, $sessionData.LognDomain.Length / 2)
            AuthenticationPackage = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.AuthenticationPackage.Buffer, $sessionData.AuthenticationPackage.Length / 2)
            LogonType = $sessionData.LogonType
            Session = $sessionData.Session
            Sid = New-Object -TypeName System.Security.Principal.SecurityIdentifier($sessionData.PSiD)
            LogonTime = $sessionData.LogonTime #(GetDateTimeFromFileTime -FileTime $sessionData.LogonTime)
            LogonServer = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonServer.Buffer, $sessionData.LogonServer.Length / 2)
            DnsDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.DnsDomainName.Buffer, $sessionData.DnsDomainName.Length / 2)
            Upn =  [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Upn.Buffer, $sessionData.Upn.Length / 2)
            UserFlags = $sessionData.UserFlags
            LastSuccessfulLogon = $sessionData.LastLogonInfo.LastSuccessfulLogon #(GetDateTimeFromFileTime -FileTime $sessionData.LastLogonInfo.LastSuccessfulLogon)
            LastFailedLogon = $sessionData.LastLogonInfo.LastFailedLogon #(GetDateTimeFromFileTime -FileTime $sessionData.LastLogonInfo.LastFailedLogon)
            FailedAttemptCountSinceLastSuccessfulLogon = $sessionData.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon
            LogonScript = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonScript.Buffer, $sessionData.LogonScript.Length / 2)
            ProfilePath = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.ProfilePath.Buffer, $sessionData.ProfilePath.Length / 2)
            HomeDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.HomeDirectory.Buffer, $sessionData.HomeDirectory.Length / 2)
            HomeDirectoryDrive = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.HomeDirectoryDrive.Buffer, $sessionData.HomeDirectoryDrive.Length / 2)
            LogoffTime = $sessionData.LogoffTime #(GetDateTimeFromFileTime -FileTime $sessionData.LogoffTime)
            KickOffTime = $sessionData.KickOffTime #(GetDateTimeFromFileTime -FileTime $sessionData.KickOffTime)
            PasswordLastSet = $sessionData.PasswordLastSet #(GetDateTimeFromFileTime -FileTime $sessionData.PasswordLastSet)
            PasswordCanChange = $sessionData.PasswordCanChange #(GetDateTimeFromFileTime -FileTime $sessionData.PasswordCanChange)
            PasswordMustChange = $sessionData.PasswordMustChange #(GetDateTimeFromFileTime -FileTime $sessionData.PasswordMustChange)
        }
                    
        $obj = New-Object -TypeName psobject -Property $props

        Write-Output $obj
    }
    catch
    {

    }

    #LsaFreeReturnBuffer -Buffer $sessionDataPtr
}

function LsaLookupAuthenticationPackage
{
    <#
    .SYNOPSIS

    The LsaLookupAuthenticationPackage function obtains the unique identifier of an authentication package.

    .DESCRIPTION

    The authentication package identifier is used in calls to authentication functions such as LsaLogonUser and LsaCallAuthenticationPackage.

    .PARAMETER LsaHandle

    Handle obtained from a previous call to LsaRegisterLogonProcess or LsaConnectUntrusted.

    .PARAMETER PackageName

    Specifies the name of the authentication package. Supported packages are 'MSV1_0_PACKAGE_NAME', 'MICROSOFT_KERBEROS_NAME_A', 'NEGOSSP_NAME_A', and 'NTLMSP_NAME_A'.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Function Dependencies: PSReflect, LsaNtStatusToWinError, LSA_STRING (Structure)
    Optional Dependencies: None

    (func secur32 LsaLookupAuthenticationPackage ([UInt32]) @(
        [IntPtr],                           #_In_  HANDLE      LsaHandle,
        $LSA_UNICODE_STRING.MakeByRefType() #_In_  PLSA_STRING PackageName,
        [UInt64].MakeByRefType()            #_Out_ PULONG      AuthenticationPackage
    ) -EntryPoint LsaLookupAuthenticationPackage)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378297(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaConnectUntrusted

    LsaLookupAuthenticationPackage -LsaHandle $hLsa -PackageName MICROSOFT_KERBEROS_NAME_A
    2
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $LsaHandle,

        [Parameter(Mandatory = $true)]
        [ValidateSet('MSV1_0_PACKAGE_NAME', 'MICROSOFT_KERBEROS_NAME_A', 'NEGOSSP_NAME_A', 'NTLMSP_NAME_A')]
        [string]
        $PackageName
    )

    switch($PackageName)
    {
        MSV1_0_PACKAGE_NAME {$authPackageName = 'NTLM'; break}
        MICROSOFT_KERBEROS_NAME_A {$authPackageName = 'Kerberos'; break}
        NEGOSSP_NAME_A {$authPackageName = 'Negotiate'; break}
        NTLMSP_NAME_A {$authPackageName = 'NTLM'; break}
    }

    $authPackageArray = [System.Text.Encoding]::ASCII.GetBytes($authPackageName)
    [int]$size = $authPackageArray.Length
    [IntPtr]$pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size) 
    [System.Runtime.InteropServices.Marshal]::Copy($authPackageArray, 0, $pnt, $authPackageArray.Length)
    
    $lsaString = [Activator]::CreateInstance($LSA_STRING)
    $lsaString.Length = [UInt16]$authPackageArray.Length
    $lsaString.MaximumLength = [UInt16]$authPackageArray.Length
    $lsaString.Buffer = $pnt
    
    $AuthenticationPackage = [UInt64]0

    $SUCCESS = $Secur32::LsaLookupAuthenticationPackage($LsaHandle, [ref]$lsaString, [ref]$AuthenticationPackage)
    
    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaLookupAuthenticationPackage Error: $($LastError.Message)"
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pnt)

    Write-Output $AuthenticationPackage
}

function LsaNtStatusToWinError
{
    <#
    .SYNOPSIS

    The LsaNtStatusToWinError function converts an NTSTATUS code returned by an LSA function to a Windows error code.

    .PARAMETER NtStatus

    An NTSTATUS code returned by an LSA function call. This value will be converted to a System error code.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms721800(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $NtStatus
    )

    <#
    (func advapi32 LsaNtStatusToWinError ([UInt64]) @(
        [UInt32] #_In_ NTSTATUS Status
    ) -EntryPoint LsaNtStatusToWinError),
    #>

    $STATUS = $Advapi32::LsaNtStatusToWinError($NtStatus)

    Write-Output $STATUS
}

function LsaRegisterLogonProcess
{
    <#
    .SYNOPSIS

    The LsaLookupAuthenticationPackage function obtains the unique identifier of an authentication package.

    .DESCRIPTION

    The authentication package identifier is used in calls to authentication functions such as LsaLogonUser and LsaCallAuthenticationPackage.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, LsaNtStatusToWinError (Function), LSA_STRING (Structure)
    Optional Dependencies: None

    (func secur32 LsaRegisterLogonProcess ([UInt32]) @(
        $LSA_STRING.MakeByRefType() #_In_  PLSA_STRING           LogonProcessName,
        [IntPtr].MakeByRefType()    #_Out_ PHANDLE               LsaHandle,
        [UInt64].MakeByRefType()    #_Out_ PLSA_OPERATIONAL_MODE SecurityMode
    ) -EntryPoint LsaRegisterLogonProcess)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378297(v=vs.85).aspx

    .EXAMPLE

    $hLsa = LsaRegisterLogonProcess
    #>

    $lsaStringArray = [System.Text.Encoding]::ASCII.GetBytes("INVOKE-IR")
    [int]$size = $lsaStringArray.Length
    [IntPtr]$pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size) 
    [System.Runtime.InteropServices.Marshal]::Copy($lsaStringArray, 0, $pnt, $lsaStringArray.Length)
    
    $lsaString = [Activator]::CreateInstance($LSA_STRING)
    $lsaString.Length = [UInt16]$lsaStringArray.Length
    $lsaString.MaximumLength = [UInt16]$lsaStringArray.Length
    $lsaString.Buffer = $pnt

    $LsaHandle = [IntPtr]::Zero
    $SecurityMode = [UInt64]0

    $SUCCESS = $Secur32::LsaRegisterLogonProcess([ref]$lsaString, [ref]$LsaHandle, [ref]$SecurityMode)

    if($SUCCESS -ne 0)
    {
        $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
        $LastError = [ComponentModel.Win32Exception]$WinErrorCode
        throw "LsaRegisterLogonProcess Error: $($LastError.Message)"
    }

    Write-Output $LsaHandle
}

function NtQueryInformationThread
{
    <#
    .SYNOPSIS

    Retrieves information about the specified thread.

    .DESCRIPTION

    .PARAMETER ThreadHandle

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    ))

    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle  
    )

    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)

    $Success = $Ntdll::NtQueryInformationThread($ThreadHandle, 9, $buf, [IntPtr]::Size, [IntPtr]::Zero); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "NtQueryInformationThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf))
}

function OpenProcess
{
    <#
    .SYNOPSIS

    Opens an existing local process object.

    .DESCRIPTION

    To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
    The handle returned by the OpenProcess function can be used in any function that requires a handle to a process, such as the wait functions, provided the appropriate access rights were requested.
    When you are finished with the handle, be sure to close it using the CloseHandle function.

    .PARAMETER ProcessId

    The identifier of the local process to be opened.
    If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.

    .PARAMETER DesiredAccess

    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, PROCESS_ACCESS (Enumeration)
    Optional Dependencies: None

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwProcessId
    ) -EntryPoint OpenProcess -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('PROCESS_TERMINATE','PROCESS_CREATE_THREAD','PROCESS_VM_OPERATION','PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_DUP_HANDLE','PROCESS_CREATE_PROCESS','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_SUSPEND_RESUME','PROCESS_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','PROCESS_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val
    }

    $hProcess = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0) 
    {
        throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hProcess
}

function OpenProcessToken
{ 
    <#
    .SYNOPSIS

    The OpenProcessToken function opens the access token associated with a process.

    .PARAMETER ProcessHandle

    A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
    For a list of access rights for access tokens, see Access Rights for Access-Token Objects.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, TOKEN_ACCESS (Enumeration)
    Optional Dependencies: None

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess  
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function OpenThread
{
    <#
    .SYNOPSIS

    Opens an existing thread object.

    .DESCRIPTION

    The handle returned by OpenThread can be used in any function that requires a handle to a thread, such as the wait functions, provided you requested the appropriate access rights. The handle is granted access to the thread object only to the extent it was specified in the dwDesiredAccess parameter.
    When you are finished with the handle, be sure to close it by using the CloseHandle function.

    .PARAMETER ThreadId

    The identifier of the thread to be opened.

    .PARAMETER DesiredAccess

    The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    
    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, THREAD_ACCESS (Enumeration)
    Optional Dependencies: None

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwThreadId
    ) -EntryPoint OpenThread -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ThreadId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('THREAD_TERMINATE','THREAD_SUSPEND_RESUME','THREAD_GET_CONTEXT','THREAD_SET_CONTEXT','THREAD_SET_INFORMATION','THREAD_QUERY_INFORMATION','THREAD_SET_THREAD_TOKEN','THREAD_IMPERSONATE','THREAD_DIRECT_IMPERSONATION','THREAD_SET_LIMITED_INFORMATION','THREAD_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','THREAD_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
    
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $THREAD_ACCESS::$val
    }

    $hThread = $Kernel32::OpenThread($dwDesiredAccess, $InheritHandle, $ThreadId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hThread -eq 0) 
    {
        throw "OpenThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hThread
}

function OpenThreadToken
{
    <#
    .SYNOPSIS

    The OpenThreadToken function opens the access token associated with a thread

    .DESCRIPTION

    Tokens with the anonymous impersonation level cannot be opened.
    Close the access token handle returned through the Handle parameter by calling CloseHandle.

    .PARAMETER ThreadHandle

    A handle to the thread whose access token is opened.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are reconciled against the token's discretionary access control list (DACL) to determine which accesses are granted or denied.

    .PARAMETER OpenAsSelf

    TRUE if the access check is to be made against the process-level security context.
    FALSE if the access check is to be made against the current security context of the thread calling the OpenThreadToken function.
    The OpenAsSelf parameter allows the caller of this function to open the access token of a specified thread when the caller is impersonating a token at SecurityIdentification level. Without this parameter, the calling thread cannot open the access token on the specified thread because it is impossible to open executive-level objects by using the SecurityIdentification impersonation level.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, $TOKEN_ACCESS (Enumeration)
    Optional Dependencies: None

    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                #_In_  HANDLE  ThreadHandle
      [UInt32],                #_In_  DWORD   DesiredAccess
      [bool],                  #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenThreadToken -SetLastError)
        
    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379296(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $OpenAsSelf = $false   
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenThreadToken($ThreadHandle, $dwDesiredAccess, $OpenAsSelf, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function RevertToSelf
{
    <#
    .SYNOPSIS

    The RevertToSelf function terminates the impersonation of a client application.

    .DESCRIPTION

    A process should call the RevertToSelf function after finishing any impersonation begun by using the DdeImpersonateClient, ImpersonateDdeClientWindow, ImpersonateLoggedOnUser, ImpersonateNamedPipeClient, ImpersonateSelf, ImpersonateAnonymousToken or SetThreadToken function.
    
    An RPC server that used the RpcImpersonateClient function to impersonate a client must call the RpcRevertToSelf or RpcRevertToSelfEx to end the impersonation.
    
    If RevertToSelf fails, your application continues to run in the context of the client, which is not appropriate. You should shut down the process if RevertToSelf fails.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func advapi32 RevertToSelf ([bool]) @(
    
    ) -EntryPoint RevertToSelf -SetLastError)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379317(v=vs.85).aspx

    .EXAMPLE

        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        NT AUTHORITY\SYSTEM

        RevertToSelf

        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        hunt.local\jared
    #>

    [CmdletBinding()]
    param
    (

    )

    $SUCCESS = $Advapi32::RevertToSelf(); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if(-not $SUCCESS)
    {
        throw "RevertToSelf Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function VirtualQueryEx
{
    <#
    .SYNOPSIS

    Retrieves information about a range of pages within the virtual address space of a specified process.

    .PARAMETER ProcessHandle

    A handle to the process whose memory information is queried. The handle must have been opened with the PROCESS_QUERY_INFORMATION access right, which enables using the handle to read information from the process object.

    .PARAMETER BaseAddress

    The base address of the region of pages to be queried. This value is rounded down to the next page boundary.
    
    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect, MEMORY_BASIC_INFORMATION (Structure), MEMORY_PROTECTION (Enumeration), MEMORY_STATE (Enumeration), MEMORY_TYPE (Enumeration)
    Optional Dependencies: None

    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORY_BASIC_INFORMATION.MakeByRefType(), #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -EntryPoint VirtualQueryEx -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress
    )
    
    $memoryinfo = [Activator]::CreateInstance($MEMORY_BASIC_INFORMATION)
    $Success = $Kernel32::VirtualQueryEx($ProcessHandle, $BaseAddress, [Ref]$memoryinfo, $MEMORY_BASIC_INFORMATION::GetSize()); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "VirtualQueryEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $memoryinfo
}

#endregion Windows API Functions

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace GetToken
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Secur32 = $Types['secur32']

#endregion PSReflect Definitions

Get-SOHostData