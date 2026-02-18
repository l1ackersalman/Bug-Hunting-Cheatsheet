## Index

1. [ATO via Password Reset](#ATO-via-Password-Reset)
1. [Unprotected Functionality](#Unprotected-functionality)
2. [Parameter-Based Access Control](#Parameter-based-access-control)
3. [Broken Access Control Resulting from Platform Misconfiguration (URL and Method-Based)](#Broken-access-control-resulting-from-platform-misconfiguration-Url-and-Method-based)
4. [Referer-Based Access Control](#Referer-based-access-control)
5. [Using Shodan](#Using-Shodan)
6. [Using Burp Intruder](#Using-Burp-Intruder)

---

### ATO via Password Reset
```
 "user" {
     "email" [
              "victim@gmail.com",
              "attacker@gmail.com"
       ]
 }
```

PoC: [Account Takeover via Password Reset without user interactions in Gitlab](https://hackerone.com/reports/2293343)
___
### Unprotected functionality

    admin
    administrator
    administrator-panel
    robots.txt
___
### Parameter based access control 
Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

    A hidden field.
    A cookie.
    A preset query string parameter.

The application makes access control decisions based on the submitted value. For example:
```
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
https://insecure-website.com/myaccount?id=123
```
In some applications, instead of an incrementing number, an application might use globally unique identifiers (GUIDs) to identify users. This may prevent an attacker from guessing or predicting another user's identifier.
However, the GUIDs belonging to other users might be disclosed elsewhere in the application.
___
### Broken access control resulting from platform misconfiguration Url and Method based
Some applications enforce access controls at the platform layer by restricting access to specific URLs and HTTP methods based on the user's role. In such cases, it may be possible to access certain endpoints by changing the request method from `POST to GET` or vice versa.<br>
<br>
Also some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as X-Original-URL and X-Rewrite-URL.
```txt
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
```
___
### Referer based access control
Some websites impliment access controls on the Referer header submitted in the HTTP request. For example, an application robustly enforces access control over the main administrative page at `/admin`, but for sub-pages such as `/admin/deleteUser` only inspects the Referer header. If the Referer header contains the main /admin URL, then the request is allowed.
<br>
```txt
Referrer: https://example.com/admin/
```
In this case, the Referer header can be fully controlled by an attacker. This means that they can forge direct requests to sensitive sub-pages like `https://example.com/admin/deleteUser` by supplying the required Referer header, and gain unauthorized access.
___
### Using Shodan
```txt
ssl:redacted.com http.html:admin
```
### Using Burp Intruder
```txt
https://web.archive.org/web/20230204201819/https://amineaboud.medium.com/story-of-a-weird-vulnerability-i-found-on-facebook-fc0875eb5125
```
