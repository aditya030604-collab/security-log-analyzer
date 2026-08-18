# Security Log Analyzer

A Python-based Security Log Analyzer that parses security log files, detects failed login attempts, identifies suspicious IP addresses, detects possible brute-force attacks, and generates a security assessment report.

## Features

* Read and parse security log files
* Validate log entries and detect malformed logs
* Count INFO, ERROR, and WARNING log entries
* Extract usernames and source IP addresses
* Detect failed login attempts
* Analyze failed login attempts by IP address
* Identify suspicious IP addresses
* Detect possible brute-force attacks
* Assign security severity levels
* Calculate an overall security risk level
* Generate a detailed security report
* Handle missing and empty log files safely
* Support command-line log file input

## Security Detection

The analyzer currently uses the following logic:

| Detection                   | Severity |
| --------------------------- | -------- |
| INFO event                  | LOW      |
| WARNING event               | MEDIUM   |
| ERROR event                 | MEDIUM   |
| Suspicious IP               | MEDIUM   |
| Possible brute-force attack | HIGH     |

A possible brute-force attack is detected when an IP address has at least 3 failed login attempts within 60 seconds.

## Technologies Used

* Python 3
* File Handling
* Dictionaries
* Functions
* Exception Handling
* `datetime`
* Command-Line Arguments

## Project Structure

```text
Security-Log-Analyzer/
│
├── analyzer.py
├── logs/
│   ├── sample.log
│   ├── normal.log
│   ├── brute_force.log
│   ├── suspicious.log
│   ├── invalid.log
│   └── empty.log
│
├── README.md
├── Requirements.txt
└── .gitignore
```

## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/aditya030604-collab/security-log-analyzer
cd Security-Log-Analyzer
```

### 2. Run with a log file

```bash
python analyzer.py logs/sample.log
```

### 3. Interactive mode

You can also run the analyzer without specifying a log file:

```bash
python analyzer.py
```

The program will ask:

```text
Enter the path to the log file:
```

Enter the path to your log file.

## Sample Test Cases

### Normal Logs

```bash
python analyzer.py logs/normal.log
```

Tests normal INFO, WARNING, and other valid log activity.

### Brute-Force Detection

```bash
python analyzer.py logs/brute_force.log
```

Tests detection of 3 failed login attempts from the same IP within 60 seconds.

Expected risk level:

```text
Overall Risk : HIGH
```

### Suspicious IP Detection

```bash
python analyzer.py logs/suspicious.log
```

Tests multiple failed login attempts that do not meet the brute-force threshold.

Expected risk level:

```text
Overall Risk : MEDIUM
```

### Invalid Log Handling

```bash
python analyzer.py logs/invalid.log
```

Tests malformed log entries and verifies that the analyzer handles them without crashing.

### Empty Log Handling

```bash
python analyzer.py logs/empty.log
```

Tests the analyzer's handling of an empty log file.

Expected output:

```text
Error: log file is empty
```

## Generated Report

After analysis, the program generates:

```text
security_report.txt
```

The report contains:

* Report generation timestamp
* Overall security risk
* Total log entries
* Valid log entries
* Invalid log entries
* INFO/ERROR/WARNING counts
* Failed login attempts
* Failed login analysis by IP
* Suspicious IP analysis
* Security findings
* Brute-force detection results

The generated report is excluded from Git tracking using `.gitignore`.

## Example Detection

For multiple failed login attempts from the same IP, the analyzer can produce:

```text
Possible Brute Force Attack
IP Address       : 192.168.1.15
Failed Attempts  : 3
```

The analyzer also identifies suspicious IP addresses based on repeated failed login attempts.

## Error Handling

The analyzer safely handles:

* Missing log files
* Empty log files
* Invalid timestamps
* Invalid log levels
* Malformed log entries

Invalid entries are counted and excluded from the valid log analysis.

## Future Improvements

Possible future enhancements include:

* Real-time log monitoring
* Additional attack-pattern detection
* Authentication anomaly detection
* CSV/JSON report export
* Visualization dashboard
* Configurable detection thresholds
* Automated alerting
* Integration with SIEM platforms

## Author

Aditya Sharma

## License

This project is intended for educational and cybersecurity portfolio purposes.
