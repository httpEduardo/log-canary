# log-canary

`log-canary` scans web server access logs for requests that resemble common attacks, then summarizes the sources, categories, and HTTP responses. It is intended for quick triage when reviewing server activity or investigating a suspicious request.

When something feels off on a web server, the access log is usually the first place to look, but grepping for `union select` by hand misses anything URL-encoded and drowns you in noise. log-canary parses each line properly, decodes the request before matching, and gives you a short report you can act on.

## Detections

| Category | Looks for | Checked in |
|----------|-----------|------------|
| `sqli` | `union select`, `' or '1'='1`, `sleep(`, `benchmark(`, `information_schema` | request |
| `xss` | `<script`, `javascript:`, inline event handlers, `<svg on…>` | request |
| `traversal` | `../` and `..\` | request |
| `cmd-injection` | `; id`, `| whoami`, backticks, `$(…)`, `/bin/sh` | request |
| `sensitive-file` | `/etc/passwd`, `win.ini`, `/.env`, `/.git/`, `wp-config.php` | request |
| `jndi` | `${jndi:` (Log4Shell) | request and User-Agent |
| `scanner` | sqlmap, Nikto, Nuclei, Nmap, gobuster, ffuf, WPScan… | User-Agent |

Requests are percent-decoded (twice, to catch double encoding) and `+` is read as a space before matching, so `union+select` and `%3Cscript%3E` are caught. The User-Agent is matched separately, so a browser string can't trigger path-based rules.

The report counts how many requests in each category received a **2xx response**. A successful response is a useful signal for investigation, but it does not prove that an attack succeeded.

## Requirements

- Rust 2021 edition (install Rust with [rustup](https://rustup.rs/))

## Usage

```bash
cargo run --release -- --input /var/log/nginx/access.log --top 10
```

```text
Lines scanned: 8 (0 not in a recognized log format)
Suspicious requests: 5

Top sources:
  10.0.0.5                                 2
  10.0.0.11                                1
  10.0.0.7                                 1
  2001:db8::7                              1

By category (hits / answered with 2xx):
  sqli               2 / 2
  jndi               1 / 1
  scanner            1 / 1
  sensitive-file     1 / 0
  traversal          1 / 0
  xss                1 / 1

Samples:
  [sqli           200] 10.0.0.5 - - [14/Jan/2026:12:00:01 +0000] "GET /search?q=union+select+1,2,3 HTTP/1.1" ...
```

## Options

- `--input`, `-i` — access log in Common or Combined Log Format (nginx and Apache defaults)
- `--top`, `-n` — how many sources and samples to show (default 5)

## Exit status

- `0` — no suspicious requests found
- `1` — at least one suspicious request found
- `2` — invalid arguments or the input file could not be read

## Building

```bash
cargo build --release
cargo test
```

## Limitations

Signature matching finds the obvious and the lazy. It won't catch novel payloads or attacks sent in POST bodies (which access logs don't record), and a match doesn't mean the attack worked. Use it for triage and as a starting point for investigation.

## License

[MIT](LICENSE)
