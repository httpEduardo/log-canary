use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::process::ExitCode;

/// One parsed line of a Common/Combined Log Format access log.
struct Request<'a> {
    ip: &'a str,
    target: String, // decoded request target (path + query)
    status: u16,
    agent: &'a str,
    raw: &'a str,
}

struct Detector {
    label: &'static str,
    pattern: Regex,
    /// Match against the User-Agent instead of the request target.
    on_agent: bool,
}

fn detectors() -> Vec<Detector> {
    let d = |label, pattern: &str, on_agent| Detector {
        label,
        pattern: Regex::new(pattern).expect("invalid built-in pattern"),
        on_agent,
    };
    vec![
        d(
            "sqli",
            r"(?i)(union\s+(all\s+)?select|'\s*or\s+'?\d+'?\s*=\s*'?\d|\bor\s+1\s*=\s*1\b|sleep\s*\(|benchmark\s*\(|information_schema|;\s*drop\s+table)",
            false,
        ),
        d(
            "xss",
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+\s*=|<img[^>]+src)",
            false,
        ),
        d("traversal", r"(\.\./|\.\.\\)", false),
        d(
            "cmd-injection",
            r"(?i)(;\s*(cat|id|whoami|uname|curl|wget)\b|\|\s*(id|whoami|sh)\b|`[^`]+`|\$\([^)]+\)|/bin/(ba)?sh)",
            false,
        ),
        d(
            "sensitive-file",
            r"(?i)(/etc/passwd|/etc/shadow|win\.ini|/\.env\b|/\.git/|wp-config\.php)",
            false,
        ),
        d("jndi", r"(?i)\$\{\s*jndi\s*:", false),
        d("jndi", r"(?i)\$\{\s*jndi\s*:", true),
        d(
            "scanner",
            r"(?i)(sqlmap|nikto|nuclei|nmap|masscan|dirbuster|gobuster|ffuf|wpscan|acunetix)",
            true,
        ),
    ]
}

/// Percent-decodes a request target, treating '+' as a space.
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_line<'a>(line: &'a str, re: &Regex) -> Option<Request<'a>> {
    let caps = re.captures(line)?;
    let target = caps.name("target").map_or("", |m| m.as_str());
    // Decode twice to catch double encoding such as %252e%252e.
    let target = decode(&decode(target));
    Some(Request {
        ip: caps.name("ip")?.as_str(),
        target,
        status: caps.name("status")?.as_str().parse().ok()?,
        agent: caps.name("agent").map_or("", |m| m.as_str()),
        raw: line,
    })
}

/// Matches Common and Combined Log Format lines (IPv4 or IPv6 clients).
fn log_regex() -> Regex {
    Regex::new(r#"^(?P<ip>\S+) \S+ \S+ \[[^\]]*\] "(?:\S+ )?(?P<target>[^"]*?)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agent>[^"]*)")?"#).expect("invalid log pattern")
}

struct Options {
    input: String,
    top: usize,
}

fn parse_args() -> Result<Options, String> {
    let mut opts = Options {
        input: "sample.log".into(),
        top: 5,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" | "-i" => opts.input = args.next().ok_or("--input needs a value")?,
            "--top" | "-n" => {
                opts.top = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|&n| n > 0)
                    .ok_or("--top needs a positive number")?
            }
            "--help" | "-h" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(opts)
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}");
            }
            eprintln!("usage: log-canary [--input FILE] [--top N]");
            return ExitCode::from(2);
        }
    };
    let raw = match fs::read_to_string(&opts.input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", opts.input);
            return ExitCode::from(2);
        }
    };

    let line_re = log_regex();
    let detectors = detectors();

    let mut lines = 0;
    let mut unparsed = 0;
    let mut by_ip: HashMap<&str, usize> = HashMap::new();
    let mut by_label: BTreeMap<&str, (usize, usize)> = BTreeMap::new(); // (hits, successful)
    let mut samples: Vec<(&str, u16, &str)> = Vec::new();

    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        lines += 1;
        let Some(req) = parse_line(line, &line_re) else {
            unparsed += 1;
            continue;
        };
        let mut labels: Vec<&str> = detectors
            .iter()
            .filter(|d| {
                d.pattern
                    .is_match(if d.on_agent { req.agent } else { &req.target })
            })
            .map(|d| d.label)
            .collect();
        labels.dedup();
        if labels.is_empty() {
            continue;
        }
        *by_ip.entry(req.ip).or_default() += 1;
        for label in &labels {
            let entry = by_label.entry(label).or_default();
            entry.0 += 1;
            if (200..300).contains(&req.status) {
                entry.1 += 1;
            }
        }
        samples.push((labels[0], req.status, req.raw));
    }

    let suspicious: usize = by_ip.values().sum();
    println!("Lines scanned: {lines} ({unparsed} not in a recognized log format)");
    println!("Suspicious requests: {suspicious}");
    if suspicious == 0 {
        return ExitCode::SUCCESS;
    }

    println!("\nTop sources:");
    let mut ips: Vec<_> = by_ip.into_iter().collect();
    ips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (ip, n) in ips.iter().take(opts.top) {
        println!("  {ip:<40} {n}");
    }

    println!("\nBy category (hits / answered with 2xx):");
    let mut labels: Vec<_> = by_label.into_iter().collect();
    labels.sort_by(|a, b| (b.1).0.cmp(&(a.1).0).then(a.0.cmp(b.0)));
    for (label, (hits, ok)) in labels {
        println!("  {label:<15} {hits:>4} / {ok}");
    }

    println!("\nSamples:");
    for (label, status, line) in samples.iter().take(opts.top) {
        println!("  [{label:<14} {status}] {line}");
    }
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_re() -> Regex {
        log_regex()
    }

    fn labels(line: &str) -> Vec<&'static str> {
        let req = parse_line(line, &line_re()).expect("line should parse");
        detectors()
            .iter()
            .filter(|d| {
                d.pattern
                    .is_match(if d.on_agent { req.agent } else { &req.target })
            })
            .map(|d| d.label)
            .collect()
    }

    const PREFIX: &str = r#"10.0.0.5 - - [14/Jan/2026:12:00:01 +0000] "GET "#;

    fn log(target: &str, agent: &str) -> String {
        format!(r#"{PREFIX}{target} HTTP/1.1" 200 1 "-" "{agent}""#)
    }

    #[test]
    fn decodes_before_matching() {
        assert_eq!(
            labels(&log("/search?q=union+select+1,2", "Mozilla")),
            vec!["sqli"]
        );
        assert_eq!(
            labels(&log("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla")),
            vec!["xss"]
        );
        assert!(
            labels(&log("/dl?f=%252e%252e%252fetc%252fpasswd", "Mozilla")).contains(&"traversal")
        );
    }

    #[test]
    fn checks_user_agent_separately() {
        assert_eq!(labels(&log("/", "sqlmap/1.7")), vec!["scanner"]);
        assert_eq!(labels(&log("/", "${jndi:ldap://x/a}")), vec!["jndi"]);
    }

    #[test]
    fn user_agent_does_not_trigger_path_rules() {
        assert!(labels(&log("/", "Mozilla/5.0 (compatible; <script>)")).is_empty());
    }

    #[test]
    fn benign_requests_are_clean() {
        assert!(labels(&log("/assets/logo.png", "Mozilla/5.0")).is_empty());
        assert!(labels(&log("/blog/union-station-selection", "Mozilla/5.0")).is_empty());
    }

    #[test]
    fn parses_ipv6_and_common_format() {
        let line = r#"2001:db8::1 - - [14/Jan/2026:12:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0"#;
        let req = parse_line(line, &line_re()).unwrap();
        assert_eq!(req.ip, "2001:db8::1");
        assert_eq!(req.status, 404);
    }
}
