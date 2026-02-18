## Index

[Google Dorking](#Google-Dorking)
[Endpoint and JS File Analyze](#Endpoint-and-JS-File-Analyze)
[Curl](#Curl)

## Google Dorking

### **1. Discovering Login Pages:**
If you’re looking for login pages or authentication portals to test for vulnerabilities like **brute-force**, **credential stuffing**, or **authentication bypass**, Google dorking can help identify them.

- **Example:**
  ```bash
  inurl:"login" OR inurl:"signin" OR inurl:"admin" site:.com
  ```
  This will help you find pages with "login", "signin", or "admin" in the URL on `.com` sites.

### **2. Finding Admin Panels:**
Many websites mistakenly leave their admin login pages exposed. Using dorks, you can locate them easily.

- **Example:**
  ```bash
  inurl:"admin" intitle:"Admin Panel"
  ```
  This targets admin panel login pages with “Admin Panel” in the title.

### **3. Sensitive Files Discovery:**
You can find exposed files like configuration files, backup files, or private documents that may contain sensitive data (like **credentials**, **API keys**, etc.).

- **Example 1:**
  ```bash
  filetype:env "DB_PASSWORD"
  ```
  This searches for `.env` files that might contain database credentials.

- **Example 2:**
  ```bash
  filetype:bak "password"
  ```
  This looks for `.bak` backup files that may contain sensitive data.

- **Example 3:**
  ```bash
  filetype:sql inurl:".sql"
  ```
  Searching for exposed `.sql` backup files that might contain a database dump.

### **4. Searching for Exposed Directory Listings:**
Some sites may have directory listing enabled, exposing files and folders to attackers. Dorking can help you find these directories.

- **Example:**
  ```bash
  intitle:"index of" inurl:"/uploads/"
  ```
  This searches for publicly exposed directories like `/uploads/` that may contain sensitive files.

### **5. Finding Open Admin/Cloud Panels (CPanel, Webmin, etc.):**
Many web hosts leave admin panels for their hosting service exposed online. These could be vulnerable to **brute-force** or **unauthorized access**.

- **Example:**
  ```bash
  inurl:"/cpanel" OR inurl:"/webmail"
  ```
  This will find exposed cPanel or Webmail login pages.

### **6. Finding Exposed API Endpoints:**
APIs are often misconfigured, leading to vulnerabilities such as **information leakage** or **unauthorized access**. You can search for API endpoints using dorking.

- **Example:**
  ```bash
  inurl:"/api/" site:.com
  ```
  This looks for API endpoints that are publicly accessible.

### **7. Discovering Error Messages with Sensitive Information:**
Error messages can sometimes leak information about a web application’s backend, like database details or the stack trace. Dorking can help you find pages with these error messages.

- **Example:**
  ```bash
  "Warning: mysqli" OR "Warning: mysql" OR "Fatal error"
  ```
  This searches for pages that display database-related warning/error messages.

### **8. Searching for Exposed Version Numbers (for CMS, Frameworks, etc.):**
Sometimes, version numbers for frameworks, CMS, or plugins are exposed publicly, which can make it easier for attackers to exploit known vulnerabilities.

- **Example:**
  ```bash
  inurl:"wp-content" intitle:"WordPress" -site:wordpress.org
  ```
  This dork finds pages related to WordPress installations, revealing the version number and plugins.

### **9. Finding SSL/TLS Vulnerabilities:**
You can use Google Dorking to find sites with weak SSL/TLS configurations or vulnerable versions of SSL certificates.

- **Example:**
  ```bash
  "ssl certificate expired"
  ```
  This dork identifies websites with expired SSL certificates, which could indicate poor security hygiene.

### **10. Discovering Exposed Subdomains:**
Using Google Dorking to search for subdomains that are inadvertently indexed by Google can help find misconfigured or hidden services on a target domain.

- **Example:**
  ```bash
  site:*.example.com -www
  ```
  This will list all subdomains of `example.com` excluding the main `www` subdomain.

### **11. Finding Disallowed Files in Robots.txt:**
Websites often use `robots.txt` to instruct search engines about which pages or files should not be crawled. However, sometimes sensitive files are included in these disallowed lists and could be accessed by attackers.

- **Example:**
  ```bash
  inurl:robots.txt "disallow"
  ```
  This will find websites where sensitive or restricted files are mentioned in the `robots.txt`.

### **12. Leaking Credentials in URL Parameters:**
Sometimes, credentials, session tokens, or API keys are passed in URL parameters, which can be discovered via Google Dorking.

- **Example:**
  ```bash
  inurl:"password=" OR inurl:"session=" OR inurl:"token="
  ```
  This dork looks for URL parameters containing sensitive information like passwords, session IDs, or tokens.

### **13. Looking for Open Login Interfaces:**
You can identify exposed login interfaces that could be targeted for **brute-force** or **credential stuffing** attacks.

- **Example:**
  ```bash
  inurl:"/login" "site login" -site:login.com
  ```
  This searches for login interfaces without a specific domain filter.

### **14. Discovering Vulnerable Forms:**
You can search for forms that might be vulnerable to **Cross-Site Scripting (XSS)**, **SQL Injection**, or other attack vectors.

- **Example:**
  ```bash
  inurl:"/search" intitle:"search" -site:google.com
  ```
  This looks for search forms that might be vulnerable to **XSS** or **SQLi**.

### **15. Exposing Unsecured File Uploads:**
File upload functionality can sometimes be insecure, allowing malicious file uploads. Google Dorking can help you identify such features.

- **Example:**
  ```bash
  inurl:"upload" "file upload"
  ```
  This helps identify pages where file uploads are available and could be tested for vulnerabilities.

---

### **Pro Tips:**
- **Use the `site:` operator** to restrict the dork to a specific domain, limiting unnecessary results.
- **Refine searches with keywords** to identify specific types of misconfigurations (like "admin", "debug", "login", etc.).
- **Leverage Google Dorking with other recon tools** like **Subfinder**, **Amass**, or **Burp Suite** to map out a target comprehensively.

---

## Endpoint and JS File Analyze 

`katana -u https://www.google.com/help/ -jc -o jvs.txt`

## Curl
`
curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.tesla.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > out.txt
`

---
