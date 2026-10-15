# Web Attack Detection with Splunk

A DVWA lab for tracing web attack inputs into Apache access logs and writing SPL searches around the evidence that is actually available.

I tested SQL injection, reflected XSS, command injection, and local file inclusion from Kali. The main lesson was a visibility gap: the access log could show the command-injection request, but not its POST-body payload.

## Lab setup

- **Attacker:** Kali Linux.
- **Target:** Ubuntu Server 24.04, Apache, MariaDB, PHP, and DVWA.
- **Detection:** Apache access logs in Splunk, index `webattack_lab`.
- **Network:** isolated VirtualBox host-only lab.

The input is `/var/log/apache2/access.log`. Searches assume Splunk extracts `uri_query`, `uri`, `clientip`, and `status`; check those fields before relying on the queries.

## Inputs tested

These payloads belong to the local DVWA experiment:

| Test | DVWA page | Example input |
| --- | --- | --- |
| SQL injection | `/dvwa/vulnerabilities/sqli/` | `1' UNION SELECT null, version()-- -` |
| Reflected XSS | `/dvwa/vulnerabilities/xss_r/` | `<script>alert(1)</script>` |
| Command injection | `/dvwa/vulnerabilities/exec/` | `127.0.0.1; whoami` |
| Local file inclusion | `/dvwa/vulnerabilities/fi/` | `?page=../../../../etc/passwd` |

## Detection logic

URL encoding changes what the payload looks like in a log. The searches normalize plus signs and decode the query before matching patterns:

```spl
index=webattack_lab
| eval decoded_uri=urldecode(replace(uri_query, "\+", " "))
```

| Query | What it looks for |
| --- | --- |
| [SQL injection](spl-queries/sql-injection.spl) | Selected SQL keywords, Boolean patterns, and comment markers. |
| [XSS](spl-queries/xss.spl) | Script tags, event handlers, and JavaScript URI patterns. |
| [Path traversal](spl-queries/path-traversal.spl) | Traversal sequences and selected target-file names. |
| [Classification](spl-queries/attack-classification.spl) | Labels matching requests and counts them by source. |
| [Request frequency](spl-queries/frequency-based.spl) | More than ten requests per source and URI in a one-minute bucket. |

These are pattern searches, not proof of exploitation. Classification chooses the first matching category, and the frequency query identifies volume rather than a specific attack.

## The command-injection blind spot

DVWA’s exec page sends the command input in a POST body. The access log used in this lab records the request line, not that body. The original experiment showed requests to the exec endpoint without the injected command in `uri_query`.

That means the existing SPL cannot inspect the missing payload. A volume alert might flag repeated requests, but it does not establish command injection. Application/WAF audit events or carefully scoped request-body telemetry would be needed for deeper inspection. Any additional body logging also needs redaction and retention controls because requests can contain credentials or personal data.

## Limits and next steps

- The regexes cover selected examples, not all SQLi/XSS/traversal syntax or encoding variants.
- Benign inputs can match. Tune against normal traffic before promoting a search to an alert.
- Access-log fields depend on the Apache format and Splunk extraction.
- The repository contains queries and a writeup; it does not include raw captures proving each test.

Next I would add sanitized request samples, close the POST-body visibility gap, and compare detections across DVWA security levels. Prevention is separate work: prepared SQL statements, context-aware output encoding, safe file-path handling, and avoiding shell execution for user-controlled input.
