# Mini SIEM Log Analyzer

A lightweight Python-based log analyzer that detects suspicious failed login activity using a time-based detection rule.

The project was built as a learning project to practice log parsing, event correlation, time-window analysis, alert generation, and basic SIEM concepts.

---

## Features

- Reads log files line by line
- Parses:
  - Timestamp
  - IP address
  - Login status
- Tracks failed login attempts by IP address
- Uses a 60-second detection window
- Detects possible brute-force activity
- Generates structured security alerts
- Assigns alert severity
- Exports alerts to JSON
- Supports command-line arguments

---

## Detection Logic

The analyzer groups failed login attempts by IP address.

For each IP address, it checks whether multiple failed login attempts occurred inside a 60-second window.

Current detection rule:

```text
3-4 failed login attempts within 60 seconds
→ MEDIUM severity

5 or more failed login attempts within 60 seconds
→ HIGH severity
```

Example:

```text
14:20:01 - Login_Failed
14:20:12 - Login_Failed
14:20:29 - Login_Failed
14:20:55 - Login_Failed
```

These events belong to the same time window and may trigger an alert.

---

## Example Input

Example `sample_logs.txt`:

```text
2026-04-15 14:20:01 192.168.1.10 Login_Failed
2026-04-15 14:20:12 192.168.1.10 Login_Failed
2026-04-15 14:20:29 192.168.1.10 Login_Failed
2026-04-15 14:20:55 192.168.1.10 Login_Failed
2026-04-15 14:21:40 192.168.1.10 Login_Success

2026-04-15 14:31:10 10.0.0.8 Login_Failed
2026-04-15 14:31:22 10.0.0.8 Login_Failed
2026-04-15 14:31:35 10.0.0.8 Login_Failed
2026-04-15 14:31:47 10.0.0.8 Login_Failed
2026-04-15 14:31:59 10.0.0.8 Login_Failed
```

---

## Example Alert

```text
[MEDIUM] 192.168.1.10 triggered 4 failed logins within 60 seconds.
Time: 2026-04-15 14:20:01 -> 2026-04-15 14:20:55

[HIGH] 10.0.0.8 triggered 5 failed logins within 60 seconds.
Time: 2026-04-15 14:31:10 -> 2026-04-15 14:31:59
```

---

## JSON Output

Detected alerts are exported as structured JSON.

Example:

```json
[
    {
        "ip": "192.168.1.10",
        "rule": "Brute Force Detection",
        "severity": "MEDIUM",
        "failed_attempts": 4,
        "window_seconds": 60,
        "start_time": "2026-04-15 14:20:01",
        "end_time": "2026-04-15 14:20:55"
    }
]
```

---

## Usage

### Requirements

- Python 3

No third-party packages are required.

### Run

```bash
python analyzer.py -f sample_logs.txt
```

You can specify a custom JSON output file:

```bash
python analyzer.py -f sample_logs.txt -o report.json
```

### Arguments

```text
-f, --file      Log file to analyze
-o, --output    JSON output file
```

Default output:

```text
alerts.json
```

---

## Project Structure

```text
mini-siem-log-analyzer/
│
├── analyzer.py
├── sample_logs.txt
├── README.md
├── .gitignore
├── LICENSE
└── examples/
    └── sample_alerts.json
```

---

## Concepts Practiced

This project was created to practice:

- Log parsing
- File I/O
- Python dictionaries and lists
- Event grouping
- `datetime`
- Time difference calculations
- Sliding time-window detection
- Rule-based security detection
- Severity classification
- Structured alerts
- JSON serialization
- Command-line interfaces with `argparse`
- Basic SIEM and blue-team concepts

---

## Current Limitations

The current version is intentionally simple.

- Supports one predefined log format
- Detects only failed-login patterns
- Uses a fixed 60-second time window
- Uses fixed detection thresholds
- Does not perform real-time monitoring
- Does not currently parse common production log formats such as Syslog, Windows Event Logs, or web server logs

---

## Future Improvements

Possible future versions may include:

- Configurable detection thresholds
- Configurable time windows
- Multiple detection rules
- HTTP 404/request-spam detection
- Username-based login analysis
- Additional severity levels
- Improved malformed-log handling
- Regex-based log parsing
- Support for multiple log formats
- Real-time log monitoring
- Alert logging
- CSV export
- Statistics and summary reports

---

## Version

**Current Version:** `v1.0`

The core failed-login detection engine is complete.

---

## Disclaimer

This project was created for **educational purposes and defensive security learning**.

It is intended to demonstrate basic log analysis, event correlation, and SIEM detection concepts using Python.