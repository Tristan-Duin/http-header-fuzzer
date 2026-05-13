# http-header-fuzzer

Test how your web server handles bad HTTP headers. Sends malicious and malformed values across 60+ headers and tells you what broke. Easy and quick way to find what needs focus for improving your defensive cybersecurity practices.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Run

```bash
httpfuzz --url https://example.com
```

That's it. This fuzzes every default header with every strategy and shows you anything unusual.

You can also run it with `python -m fuzzer --url https://example.com`.

## Pick what to test

Fuzz only specific headers:
```bash
httpfuzz -u https://example.com --header-names Host Cookie User-Agent
```

Use only certain strategies:
```bash
httpfuzz -u https://example.com -s sql_injection xss
```

Combine both:
```bash
httpfuzz -u https://example.com --header-names Cookie -s xss crlf_injection
```

## Strategies

- `overflow` - long strings (100 to 100k chars)
- `sql_injection` - SQL probe strings
- `xss` - script tags, event handlers, template injection
- `crlf_injection` - newline injection for header splitting
- `format_string` - `%s`, `%x`, `%n` patterns
- `null_byte` - null bytes in different positions
- `unicode` - BOM, overlong UTF-8, fullwidth, surrogates
- `integer` - boundary values, MAX_INT, NaN, Infinity
- `command_injection` - shell metacharacters

All strategies run by default. Use `-s` to pick specific ones.

## Save results

```bash
# JSON
httpfuzz -u https://target.com --output json -o results.json

# CSV
httpfuzz -u https://target.com --output csv -o results.csv
```

## Tune performance

```bash
# 50 concurrent requests, 5 second timeout
httpfuzz -u https://target.com -c 50 -t 5

# Add delay between requests (seconds)
httpfuzz -u https://target.com --delay 0.1
```

## Use a proxy

```bash
httpfuzz -u https://target.com --proxy http://127.0.0.1:8080
```

## Other useful flags

- `--exploitable` - only show the most exploitable findings (CRIT/HIGH severity, deduplicated)
- `--all` - show every result, not just the interesting ones
- `--method POST` - use a different HTTP method
- `--headers "Content-Type: application/json"` - add static headers to every request
- `--skip-verify` - skip TLS certificate checks
- `--custom-payloads file.txt` - add your own payloads (one per line)
- `--header-wordlist file.txt` - use your own list of header names
- `--retries N` - retry failed requests (default: 2)

## Filter to what matters

After a full scan, cut the noise and see only what's most likely exploitable:
```bash
httpfuzz -u https://target.com --exploitable
```

This filters to CRIT and HIGH severity findings (server errors, reflected payloads) and deduplicates per header + strategy so you only see the best hit for each.

Works with all output formats:
```bash
httpfuzz -u https://target.com --exploitable --output json -o top_findings.json
```

## How it works

1. Sends a normal request to get a baseline (status code, body size, response time)
2. Sends the same request with one header set to a malicious value
3. Compares each response to the baseline
4. Flags anything that looks different - status change, size shift, slow response, payload reflected back, or server error


## License

MIT

