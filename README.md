# Web Attack Detection with Splunk (DVWA)

Attacks DVWA (SQLi, XSS, Command Injection, LFI) from Kali, ingests Apache's access log into Splunk, and detects the attacks with SPL.

## Setup
- **Attacker**: Kali Linux
- **Target**: Ubuntu Server 24.04 — LAMP stack (Apache, MariaDB, PHP) + DVWA
- **SIEM**: Splunk, index `webattack_lab`
- **Network**: isolated VirtualBox host-only

Ingest `/var/log/apache2/access.log` into Splunk.

## Attacks run (from Kali)

**SQLi** — `/dvwa/vulnerabilities/sqli/`
```
1' OR '1'='1
1' AND '1'='2
1' UNION SELECT null, version()-- -
1' UNION SELECT user(), database()-- -
```

**XSS** — `/dvwa/vulnerabilities/xss_r/`
```
<script>alert('xss')</script>
<img src=x onerror=alert(1)>
```

**Command Injection** — `/dvwa/vulnerabilities/exec/`
```
127.0.0.1; whoami
127.0.0.1 && id
```

**LFI** — `/dvwa/vulnerabilities/fi/`
```
?page=../../../../etc/passwd
```

## Detection (SPL)

All queries decode the URL first, since payloads are URL-encoded in the log (`%27`, `+`):

```spl
index=webattack_lab
| eval decoded_uri=urldecode(replace(uri_query, "\+", " "))
| eval attack_type=case(
    match(decoded_uri, "(?i)(union.*select|or\s+1=1|'\s+or\s+')"), "SQL Injection",
    match(decoded_uri, "(?i)(<script|onerror\s*=|onload\s*=)"), "XSS",
    match(decoded_uri, "(\.\./|etc/passwd)"), "Path Traversal",
    true(), "Normal"
)
| where attack_type!="Normal"
| stats count by attack_type, clientip
```

Individual queries per attack type, plus a frequency-based one that catches rapid requests to any endpoint regardless of payload content: [`spl-queries/`](spl-queries/)

## Known limitation: Command Injection isn't detected

DVWA's exec page submits via POST. Apache's access log only records the request line, never the body — so the payload never appears anywhere in the log. Confirmed directly: every command injection request shows as `POST /dvwa/vulnerabilities/exec/` with no query string at all. genuine fix: a WAF (ModSecurity) or full request-body logging (`mod_dumpio`) — noted as a gap rather than solved here.

## Security fixes, ranked

1. Parameterized queries / prepared statements
2. Input validation + output encoding
3. A WAF (ModSecurity, Cloudflare)
4. Least-privilege DB accounts
5. Full request logging, not just access logs
6. Keep frameworks/plugins patched 

## What's next
- Actually fix the command-injection blind spot (WAF or `mod_dumpio`)
- Re-test payloads against DVWA medium/high security levels
- Brute-force/SQLi-bypass DVWA's login page, detect via request frequency
- Splunk vs. ELK comparison writeup across all three projects