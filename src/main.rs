use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;

#[derive(Debug)]
struct Hit {
    ip: String,
    pattern: String,
    line: String,
}

fn parse_args() -> (String, usize) {
    let args: Vec<String> = env::args().collect();
    let input = args
        .iter()
        .position(|arg| arg == "--input")
        .and_then(|idx| args.get(idx + 1))
        .cloned()
        .unwrap_or_else(|| "sample.log".to_string());
    let top = args
        .iter()
        .position(|arg| arg == "--top")
        .and_then(|idx| args.get(idx + 1))
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(5);
    (input, top)
}

fn main() {
    let (input, top) = parse_args();
    let raw = fs::read_to_string(&input).expect("Failed to read log file");

    let patterns = vec![
        ("SQLi", Regex::new(r"(?i)(union\s+select|or\s+1=1|sleep\()") .unwrap()),
        ("XSS", Regex::new(r"(?i)(<script|%3cscript)") .unwrap()),
        ("Traversal", Regex::new(r"(?i)(\.\./|%2e%2e)") .unwrap()),
        ("Command", Regex::new(r"(?i)(;\s*cat|cmd=|/bin/sh)") .unwrap()),
    ];

    let ip_re = Regex::new(r"^(\d+\.\d+\.\d+\.\d+)").unwrap();
    let mut hits: Vec<Hit> = Vec::new();

    for line in raw.lines() {
        let ip = ip_re
            .captures(line)
            .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        for (label, regex) in &patterns {
            if regex.is_match(line) {
                hits.push(Hit {
                    ip: ip.clone(),
                    pattern: label.to_string(),
                    line: line.to_string(),
                });
            }
        }
    }

    println!("Lines scanned: {}", raw.lines().count());
    println!("Suspicious hits: {}\n", hits.len());

    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    let mut pattern_counts: HashMap<String, usize> = HashMap::new();
    for hit in &hits {
        *ip_counts.entry(hit.ip.clone()).or_insert(0) += 1;
        *pattern_counts.entry(hit.pattern.clone()).or_insert(0) += 1;
    }

    println!("Top IPs:");
    let mut ip_list: Vec<_> = ip_counts.into_iter().collect();
    ip_list.sort_by(|a, b| b.1.cmp(&a.1));
    for (ip, count) in ip_list.into_iter().take(top) {
        println!("  {ip}: {count}");
    }

    println!("\nPattern counts:");
    let mut pattern_list: Vec<_> = pattern_counts.into_iter().collect();
    pattern_list.sort_by(|a, b| b.1.cmp(&a.1));
    for (pattern, count) in pattern_list {
        println!("  {pattern}: {count}");
    }

    println!("\nSample hits:");
    for hit in hits.iter().take(top) {
        println!("[{:<9}] {}", hit.pattern, hit.line);
    }
}
