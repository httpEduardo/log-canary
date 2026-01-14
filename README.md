# Log Canary

Log Canary scans web access logs and highlights suspicious patterns like SQLi, XSS, and traversal.

## Quick start

```bash
cargo run -- --input sample.log --top 5
```

## Output

- Top IPs with suspicious hits.
- Pattern counts and sample lines.
