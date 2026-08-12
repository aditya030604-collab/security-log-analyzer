# Security Log Analyzer

A Python-based Security Log Analyzer that parses log files, analyzes security events, detects failed login attempts, and identifies potential brute-force attacks.

## Features

- Read log files from a user-provided file path
- Parse and validate log entries
- Extract usernames and IP addresses
- Count INFO, ERROR, and WARNING logs
- Detect invalid or malformed log entries
- Detect failed login attempts
- Identify potential brute-force attacks based on failed login attempts within a defined time window
- Generate a structured security report
- Handle missing and empty log files gracefully

## Technologies Used

- Python 3
- Dictionaries
- Functions
- File Handling
- Exception Handling
- datetime module

## Project Structure

security-log-analyzer/
├── analyzer.py
├── logs/
│   └── sample.log
├── README.md
├── Requirements.txt
└── .gitignore

## How to Run

### 1. Clone the Repository

Clone the repository and navigate to the project directory.

### 2. Run the Analyzer

Open a terminal in the project directory and run:

python analyzer.py

### 3. Provide the Log File Path

When prompted, enter the path to the log file:

logs/sample.log

The analyzer will process the log file and display a security summary in the terminal.

### 4. Security Report

After analysis, the program generates a security_report.txt file containing:

- Log summary
- Failed login attempts
- Potential brute-force attacks

The report is generated locally and is excluded from the Git repository using .gitignore.

## Example Analysis

The analyzer can identify failed login attempts such as:

Time : 09:12:05
User : root
IP   : 192.168.1.15

It can also identify potential brute-force activity when multiple failed login attempts from the same IP address occur within the defined time window.

## Error Handling

The analyzer handles common input problems such as:

- Missing log files
- Empty log files
- Invalid log entries
- Invalid date and time formats
- Unsupported log levels

Invalid entries are skipped and counted separately instead of causing the program to terminate.

## Future Improvements

- Support Linux authentication logs
- Support Windows Event Logs
- Detect suspicious user activity
- Export reports to CSV and PDF
- Add additional security event detection
- Add configurable brute-force detection thresholds

## Author

Aditya Sharma